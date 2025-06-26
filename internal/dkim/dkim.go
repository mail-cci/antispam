package dkim

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/go-redis/redis/v8"
	mdns "github.com/miekg/dns"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

var (
	cfg                *config.Config
	rdb                *redis.Client
	logger             *zap.Logger
	workerPool         *DKIMWorkerPool
	localCache         *LocalCache
	performanceMonitor *PerformanceMonitor
)

var txtLookup = defaultLookupTXT

const (
	DKIM_SIGERROR_UNKNOWN         = -1
	DKIM_SIGERROR_VERSION         = 1
	DKIM_SIGERROR_EXPIRED         = 3
	DKIM_SIGERROR_FUTURE          = 4
	DKIM_SIGERROR_NOREC           = 6
	DKIM_SIGERROR_INVALID_HC      = 7
	DKIM_SIGERROR_INVALID_BC      = 8
	DKIM_SIGERROR_INVALID_A       = 10
	DKIM_SIGERROR_INVALID_L       = 12
	DKIM_SIGERROR_EMPTY_D         = 16
	DKIM_SIGERROR_EMPTY_S         = 18
	DKIM_SIGERROR_EMPTY_B         = 20
	DKIM_SIGERROR_NOKEY           = 22
	DKIM_SIGERROR_KEYFAIL         = 24
	DKIM_SIGERROR_EMPTY_BH        = 26
	DKIM_SIGERROR_BADSIG          = 28
	DKIM_SIGERROR_EMPTY_H         = 31
	DKIM_SIGERROR_INVALID_H       = 32
	DKIM_SIGERROR_KEYHASHMISMATCH = 37
	DKIM_SIGERROR_EMPTY_V         = 45
)

// DKIMErrorInfo provides detailed information about DKIM errors
type DKIMErrorInfo struct {
	Code        int
	Category    string
	Severity    string
	Description string
	Suggestion  string
}

var dkimErrorMap = map[string]DKIMErrorInfo{
	"empty selector": {
		Code:        DKIM_SIGERROR_EMPTY_S,
		Category:    "selector",
		Severity:    "high",
		Description: "DKIM signature missing selector field",
		Suggestion:  "Check DKIM-Signature header for 's=' tag",
	},
	"invalid selector": {
		Code:        DKIM_SIGERROR_EMPTY_S,
		Category:    "selector",
		Severity:    "high",
		Description: "DKIM selector contains invalid characters",
		Suggestion:  "Selector must contain only alphanumeric characters and hyphens",
	},
	"s tag not found": {
		Code:        DKIM_SIGERROR_EMPTY_S,
		Category:    "selector",
		Severity:    "high",
		Description: "DKIM signature missing selector tag",
		Suggestion:  "Add 's=' tag with valid selector to DKIM-Signature header",
	},
	"incompatible signature version": {
		Code:        DKIM_SIGERROR_VERSION,
		Category:    "version",
		Severity:    "medium",
		Description: "DKIM signature version not supported",
		Suggestion:  "Use DKIM version 1 (v=1)",
	},
	"signature has expired": {
		Code:        DKIM_SIGERROR_EXPIRED,
		Category:    "timing",
		Severity:    "medium",
		Description: "DKIM signature has passed expiration time",
		Suggestion:  "Check signature timestamp and expiration settings",
	},
	"no valid key found": {
		Code:        DKIM_SIGERROR_NOREC,
		Category:    "key_lookup",
		Severity:    "high",
		Description: "No DKIM public key found in DNS",
		Suggestion:  "Verify DNS TXT record at selector._domainkey.domain",
	},
	"key unavailable": {
		Code:        DKIM_SIGERROR_KEYFAIL,
		Category:    "key_lookup",
		Severity:    "high",
		Description: "DKIM public key lookup failed",
		Suggestion:  "Check DNS configuration and network connectivity",
	},
	"no key for signature": {
		Code:        DKIM_SIGERROR_NOKEY,
		Category:    "key_lookup",
		Severity:    "high",
		Description: "DKIM public key not found for this signature",
		Suggestion:  "Verify selector and domain in DKIM signature",
	},
	"multiple TXT records found for key": {
		Code:        DKIM_SIGERROR_KEYFAIL,
		Category:    "key_lookup",
		Severity:    "medium",
		Description: "Multiple DKIM key records found in DNS",
		Suggestion:  "Ensure only one DKIM key record exists per selector",
	},
	"unsupported header canonicalization algorithm": {
		Code:        DKIM_SIGERROR_INVALID_HC,
		Category:    "algorithm",
		Severity:    "medium",
		Description: "Header canonicalization algorithm not supported",
		Suggestion:  "Use 'simple' or 'relaxed' canonicalization",
	},
	"unsupported body canonicalization algorithm": {
		Code:        DKIM_SIGERROR_INVALID_BC,
		Category:    "algorithm",
		Severity:    "medium",
		Description: "Body canonicalization algorithm not supported",
		Suggestion:  "Use 'simple' or 'relaxed' canonicalization",
	},
	"malformed algorithm name": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "high",
		Description: "DKIM algorithm specification is malformed",
		Suggestion:  "Use valid algorithm like 'rsa-sha256'",
	},
	"unsupported key algorithm": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "high",
		Description: "DKIM key algorithm not supported",
		Suggestion:  "Use RSA keys with SHA-256 hashing",
	},
	"inappropriate key algorithm": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "high",
		Description: "DKIM key algorithm inappropriate for signature",
		Suggestion:  "Ensure key algorithm matches signature algorithm",
	},
	"inappropriate hash algorithm": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "high",
		Description: "Hash algorithm inappropriate for DKIM",
		Suggestion:  "Use SHA-256 instead of weaker algorithms",
	},
	"hash algorithm too weak": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "critical",
		Description: "Hash algorithm considered cryptographically weak",
		Suggestion:  "Upgrade to SHA-256 or stronger hash algorithm",
	},
	"unsupported hash algorithm": {
		Code:        DKIM_SIGERROR_INVALID_A,
		Category:    "algorithm",
		Severity:    "high",
		Description: "Hash algorithm not supported by verifier",
		Suggestion:  "Use widely supported algorithms like SHA-256",
	},
	"message contains an insecure body length tag": {
		Code:        DKIM_SIGERROR_INVALID_L,
		Category:    "security",
		Severity:    "medium",
		Description: "Body length tag creates security vulnerability",
		Suggestion:  "Remove 'l=' tag or use full body signing",
	},
	"malformed body hash": {
		Code:        DKIM_SIGERROR_EMPTY_BH,
		Category:    "hash",
		Severity:    "high",
		Description: "Body hash in signature is malformed",
		Suggestion:  "Check 'bh=' tag in DKIM signature",
	},
	"malformed signature": {
		Code:        DKIM_SIGERROR_EMPTY_B,
		Category:    "signature",
		Severity:    "high",
		Description: "DKIM signature data is malformed",
		Suggestion:  "Check 'b=' tag in DKIM signature header",
	},
	"body hash did not verify": {
		Code:        DKIM_SIGERROR_BADSIG,
		Category:    "verification",
		Severity:    "critical",
		Description: "Message body hash does not match signature",
		Suggestion:  "Message body may have been modified in transit",
	},
	"signature did not verify": {
		Code:        DKIM_SIGERROR_BADSIG,
		Category:    "verification",
		Severity:    "critical",
		Description: "DKIM signature verification failed",
		Suggestion:  "Message headers may have been modified or key mismatch",
	},
	"From field not signed": {
		Code:        DKIM_SIGERROR_INVALID_H,
		Category:    "headers",
		Severity:    "high",
		Description: "Required From header not included in signature",
		Suggestion:  "Include 'from' in 'h=' tag of DKIM signature",
	},
	"domain mismatch": {
		Code:        DKIM_SIGERROR_EMPTY_D,
		Category:    "domain",
		Severity:    "high",
		Description: "Domain in signature does not match expected domain",
		Suggestion:  "Verify 'd=' tag matches sender domain",
	},
	"incompatible public key version": {
		Code:        DKIM_SIGERROR_VERSION,
		Category:    "key",
		Severity:    "medium",
		Description: "Public key version not compatible",
		Suggestion:  "Use compatible DKIM key version",
	},
	"unsupported public key query method": {
		Code:        DKIM_SIGERROR_UNKNOWN,
		Category:    "key_lookup",
		Severity:    "low",
		Description: "Public key query method not supported",
		Suggestion:  "Use DNS TXT record method for key distribution",
	},
}

func errorCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	msg := err.Error()
	for substr, info := range dkimErrorMap {
		if strings.Contains(msg, substr) {
			return info.Code
		}
	}
	return DKIM_SIGERROR_UNKNOWN
}

// getErrorInfo returns detailed information about a DKIM error
func getErrorInfo(err error) *DKIMErrorInfo {
	if err == nil {
		return nil
	}

	msg := err.Error()
	for substr, info := range dkimErrorMap {
		if strings.Contains(msg, substr) {
			return &info
		}
	}

	// Return generic error info for unknown errors
	return &DKIMErrorInfo{
		Code:        DKIM_SIGERROR_UNKNOWN,
		Category:    "unknown",
		Severity:    "medium",
		Description: fmt.Sprintf("Unknown DKIM error: %s", msg),
		Suggestion:  "Check DKIM signature format and configuration",
	}
}

// DKIMWorkerPool manages parallel DKIM signature verification
type DKIMWorkerPool struct {
	config      types.DKIMWorkerPoolConfig
	workQueue   chan *SignatureWork
	resultQueue chan *SignatureResult
	dnsQueue    chan *DNSWork
	dnsWorkers  []*DNSWorker
	workers     []*Worker
	mu          sync.RWMutex
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// SignatureWork represents work for signature verification
type SignatureWork struct {
	ID            int
	RawEmail      []byte
	Verification  *dkim.Verification
	Domain        string
	StartTime     time.Time
	CorrelationID string
}

// SignatureResult represents the result of signature verification
type SignatureResult struct {
	ID          int
	Signature   types.DKIMSignatureResult
	Error       error
	ProcessTime time.Duration
}

// DNSWork represents DNS lookup work
type DNSWork struct {
	Domain    string
	Callback  chan *DNSResult
	StartTime time.Time
}

// DNSResult represents DNS lookup result
type DNSResult struct {
	Records []string
	TTL     uint32
	Error   error
	Cached  bool
}

// Worker handles signature verification
type Worker struct {
	id   int
	pool *DKIMWorkerPool
	ctx  context.Context
}

// DNSWorker handles DNS lookups
type DNSWorker struct {
	id   int
	pool *DKIMWorkerPool
	ctx  context.Context
}

// LocalCache provides fast in-memory caching
type LocalCache struct {
	mu      sync.RWMutex
	entries map[string]*types.DKIMCacheEntry
	maxSize int64
	curSize int64
	stats   CacheStats
}

// CacheStats tracks cache performance
type CacheStats struct {
	Hits       int64
	Misses     int64
	Evictions  int64
	TotalSize  int64
	EntryCount int64
}

// PerformanceMonitor tracks DKIM performance metrics
type PerformanceMonitor struct {
	mu                sync.RWMutex
	totalRequests     int64
	totalTime         int64
	dnsTime           int64
	cacheHits         int64
	cacheMisses       int64
	earlyTerminations int64
	parallelJobs      int64
}

// GetStats returns a copy of the performance metrics.
func (p *PerformanceMonitor) GetStats() types.DKIMPerformanceInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	totalCache := p.cacheHits + p.cacheMisses
	var hitRate float64
	if totalCache > 0 {
		hitRate = float64(p.cacheHits) / float64(totalCache)
	}

	return types.DKIMPerformanceInfo{
		ProcessingTime:   p.totalTime,
		DNSLookupTime:    p.dnsTime,
		CacheHitRate:     hitRate,
		ParallelWorkers:  int(p.parallelJobs),
		EarlyTermination: p.earlyTerminations > 0,
	}
}

// GetStats returns a copy of the local cache statistics.
func (l *LocalCache) GetStats() CacheStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	stats := l.stats
	stats.TotalSize = l.curSize
	stats.EntryCount = int64(len(l.entries))
	return stats
}

func defaultLookupTXT(ctx context.Context, domain string) ([]string, uint32, error) {
	conf, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return nil, 0, err
	}
	server := net.JoinHostPort(conf.Servers[0], conf.Port)
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeTXT)
	r, _, err := new(mdns.Client).ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	var ttl uint32
	for _, ans := range r.Answer {
		if t, ok := ans.(*mdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
			if ttl == 0 || t.Hdr.Ttl < ttl {
				ttl = t.Hdr.Ttl
			}
		}
	}
	return out, ttl, nil
}

// Init stores the application config for DKIM verification.
func Init(c *config.Config, l *zap.Logger) {
	cfg = c
	logger = l
	if cfg != nil && cfg.RedisURL != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisURL})
	} else {
		rdb = nil
	}
}

func scoreFor(valid bool) float64 {
	if valid {
		return -1
	}
	return 3
}

// scoreForWeakHash returns appropriate score for weak hash algorithms
func scoreForWeakHash() float64 {
	return 5 // Higher spam score for SHA-1 usage
}

var selectorRegexp = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// truncateString truncates a string to maxLen characters for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// addCorrelationID adds correlation ID to log fields if provided
func addCorrelationID(fields []zap.Field, correlationID string) []zap.Field {
	if correlationID != "" {
		return append(fields, zap.String("correlation_id", correlationID))
	}
	return fields
}

func parseSelector(header string) (string, error) {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "s=") {
			val := strings.TrimSpace(strings.TrimPrefix(part, "s="))
			if val == "" {
				return "", fmt.Errorf("empty selector")
			}
			if !selectorRegexp.MatchString(val) {
				return "", fmt.Errorf("invalid selector")
			}
			return val, nil
		}
	}
	return "", fmt.Errorf("s tag not found")
}

// Verify checks all DKIM signatures in the provided raw email. It returns a
// DKIMResult with Valid=true if at least one signature verifies correctly.
func Verify(rawEmail []byte) (*types.DKIMResult, error) {
	return VerifyWithCorrelationID(rawEmail, "")
}

// VerifyWithCorrelationID checks all DKIM signatures in the provided raw email with correlation ID for debugging.
func VerifyWithCorrelationID(rawEmail []byte, correlationID string) (*types.DKIMResult, error) {
	res := &types.DKIMResult{
		Signatures:          make([]types.DKIMSignatureResult, 0),
		AlignmentCandidates: make([]types.AlignmentCandidate, 0),
	}

	// Create logger with correlation ID if provided
	logFields := []zap.Field{
		zap.Int("email_size", len(rawEmail)),
		zap.String("step", "init"),
	}
	if correlationID != "" {
		logFields = append(logFields, zap.String("correlation_id", correlationID))
	}

	if logger != nil {
		logger.Debug("starting DKIM verification", logFields...)
	}

	start := time.Now()
	metrics.DKIMChecksTotal.Inc()

	// Setup a context with timeout for DNS lookups if configured.
	ctx := context.Background()
	if cfg != nil && cfg.Auth.DKIM.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Auth.DKIM.Timeout)
		defer cancel()

		if logger != nil {
			logger.Debug("context timeout configured",
				zap.String("step", "configure_timeout"),
				zap.Duration("timeout", cfg.Auth.DKIM.Timeout))
		}
	}

	lookup := func(domain string) ([]string, error) {
		if logger != nil {
			logger.Debug("DNS lookup requested",
				zap.String("step", "dns_lookup"),
				zap.String("domain", domain))
		}

		result, err := lookupTXTWithCache(ctx, domain)

		if logger != nil {
			logger.Debug("DNS lookup completed",
				zap.String("step", "dns_lookup_complete"),
				zap.String("domain", domain),
				zap.Error(err),
				zap.Int("records_count", len(result)))

			if len(result) > 0 {
				logger.Debug("DNS TXT records found",
					zap.String("step", "dns_records"),
					zap.String("domain", domain),
					zap.String("first_record_preview", truncateString(result[0], 200)))
			}
		}

		return result, err
	}

	if logger != nil {
		logger.Debug("starting DKIM verification with library",
			zap.String("step", "verify_with_library"))
	}

	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(rawEmail), &dkim.VerifyOptions{
		LookupTXT: lookup,
	})

	if logger != nil {
		logger.Debug("DKIM library verification completed",
			zap.String("step", "library_verification_complete"),
			zap.Error(err),
			zap.Int("verifications_count", len(verifs)))
	}

	if err != nil && len(verifs) == 0 {
		if logger != nil {
			logger.Debug("DKIM verification failed with no results",
				zap.String("step", "verification_failed"),
				zap.Error(err))
		}
		metrics.DKIMCheckFail.Inc()
		metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())
		return nil, err
	}

	// Initialize signature counters
	res.TotalSignatures = len(verifs)
	res.ValidSignatures = 0

	if len(verifs) == 0 {
		if logger != nil {
			logger.Debug("no DKIM signatures found",
				zap.String("step", "no_signatures"))
		}
		res.Valid = false
		res.Score = 0
		metrics.DKIMCheckFail.Inc()
		metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())
		return res, nil
	}

	if logger != nil {
		logger.Debug("processing verification results",
			zap.String("step", "process_results"),
			zap.Int("results_count", len(verifs)))
	}

	// Process each signature verification result
	for i, v := range verifs {
		if logger != nil {
			logger.Debug("processing verification result",
				zap.String("step", "process_result"),
				zap.Int("result_index", i),
				zap.String("domain", v.Domain),
				zap.Error(v.Err))
		}

		// Create detailed signature result
		sigResult := types.DKIMSignatureResult{
			Domain:    v.Domain,
			Selector:  extractSelectorFromDomain(v.Domain), // Extract from domain since it's not directly available
			Valid:     v.Err == nil,
			Algorithm: "rsa-sha256", // Default, will be enhanced later with signature parsing
		}

		// Extract additional information from verification result
		sigResult.Headers = v.HeaderKeys
		sigResult.Timestamp = v.Time.Unix()
		sigResult.Expiration = v.Expiration.Unix()
		sigResult.BodyLength = -1          // Not available in verification result
		sigResult.KeyLength = 0            // Not available in verification result
		sigResult.HashAlgorithm = "sha256" // Default, not directly available
		sigResult.WeakHash = false         // Will be determined from error message

		if v.Err != nil {
			sigResult.Error = v.Err.Error()

			// Get detailed error information
			errorInfo := getErrorInfo(v.Err)

			// Handle graceful degradation based on error type
			handleSignatureError(v.Err, &sigResult, res, errorInfo)

			if logger != nil {
				logFields := []zap.Field{
					zap.String("step", "signature_failed"),
					zap.String("domain", v.Domain),
					zap.Int("error_code", errorCodeFromError(v.Err)),
					zap.String("error_category", errorInfo.Category),
					zap.String("error_severity", errorInfo.Severity),
					zap.Error(v.Err),
				}
				if correlationID != "" {
					logFields = append(logFields, zap.String("correlation_id", correlationID))
				}
				logger.Debug("DKIM signature validation failed with detailed context", logFields...)
			}
		} else {
			res.ValidSignatures++
			if logger != nil {
				logger.Debug("valid DKIM signature found",
					zap.String("step", "valid_signature"),
					zap.String("domain", v.Domain))
			}
		}

		// Add to signatures list
		res.Signatures = append(res.Signatures, sigResult)

		// Create alignment candidate for DMARC
		alignmentCandidate := types.AlignmentCandidate{
			Domain:   v.Domain,
			Selector: sigResult.Selector,
			Valid:    sigResult.Valid,
		}
		res.AlignmentCandidates = append(res.AlignmentCandidates, alignmentCandidate)

		// Set primary domain and selector from first signature
		if res.Domain == "" {
			res.Domain = v.Domain
		}
		if res.Selector == "" {
			res.Selector = sigResult.Selector
		}
	}

	// Determine overall validity and best signature
	res.Valid = res.ValidSignatures > 0
	res.BestSignature = selectBestSignature(res.Signatures)

	// Detect edge cases and anomalies
	res.EdgeCaseInfo = detectEdgeCases(res.Signatures)

	// Calculate enhanced score based on multiple signatures with graceful degradation
	res.Score = calculateEnhancedScoreWithDegradation(res)

	// Update metrics
	if res.Valid {
		metrics.DKIMCheckPass.Inc()
	} else {
		metrics.DKIMCheckFail.Inc()
	}
	metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())

	if logger != nil {
		logger.Debug("dkim verification complete",
			zap.Bool("valid", res.Valid),
			zap.String("domain", res.Domain),
			zap.Int("valid_signatures", res.ValidSignatures),
			zap.Int("total_signatures", res.TotalSignatures),
			zap.Float64("score", res.Score),
		)
	}
	return res, nil
}

func lookupTXTWithCache(ctx context.Context, domain string) ([]string, error) {
	if logger != nil {
		logger.Debug("DNS TXT lookup with cache",
			zap.String("step", "cache_lookup_start"),
			zap.String("domain", domain))
	}

	selector := ""
	d := ""
	if parts := strings.SplitN(domain, "._domainkey.", 2); len(parts) == 2 {
		selector = parts[0]
		d = parts[1]

		if logger != nil {
			logger.Debug("parsed DKIM domain",
				zap.String("step", "parse_dkim_domain"),
				zap.String("selector", selector),
				zap.String("domain", d))
		}
	}

	cacheKey := ""
	if selector != "" && d != "" {
		cacheKey = fmt.Sprintf("dkim:key:%s:%s", selector, d)

		if logger != nil {
			logger.Debug("checking cache for DKIM key",
				zap.String("step", "cache_check"),
				zap.String("cache_key", cacheKey),
				zap.Bool("redis_available", rdb != nil))
		}

		if rdb != nil {
			if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
				if logger != nil {
					logger.Debug("DKIM key found in cache",
						zap.String("step", "cache_hit"),
						zap.String("cache_key", cacheKey),
						zap.String("value_preview", truncateString(val, 100)))
				}
				return []string{val}, nil
			} else if logger != nil {
				logger.Debug("DKIM key not found in cache",
					zap.String("step", "cache_miss"),
					zap.String("cache_key", cacheKey),
					zap.String("cache_error", err.Error()))
			}
		}
	}

	if logger != nil {
		logger.Debug("performing DNS TXT lookup",
			zap.String("step", "dns_txt_lookup"),
			zap.String("domain", domain))
	}

	txts, ttl, err := txtLookup(ctx, domain)
	if err != nil {
		if logger != nil {
			logger.Debug("DNS TXT lookup failed",
				zap.String("step", "dns_lookup_failed"),
				zap.String("domain", domain),
				zap.Error(err))
		}
		return nil, err
	}

	if logger != nil {
		logger.Debug("DNS TXT lookup successful",
			zap.String("step", "dns_lookup_success"),
			zap.String("domain", domain),
			zap.Uint32("ttl", ttl),
			zap.Int("records_count", len(txts)))
	}

	if cacheKey != "" && rdb != nil && len(txts) > 0 {
		dur := cfg.Auth.DKIM.CacheTTL
		if ttl > 0 {
			dur = time.Duration(ttl) * time.Second
		}
		if dur == 0 {
			dur = time.Hour
		}

		if logger != nil {
			logger.Debug("caching DKIM key",
				zap.String("step", "cache_store"),
				zap.String("cache_key", cacheKey),
				zap.Duration("cache_duration", dur),
				zap.String("value_preview", truncateString(txts[0], 100)))
		}

		if err := rdb.Set(ctx, cacheKey, txts[0], dur).Err(); err != nil && logger != nil {
			logger.Debug("failed to cache DKIM key",
				zap.String("step", "cache_store_failed"),
				zap.String("cache_key", cacheKey),
				zap.Error(err))
		}
	}
	return txts, nil
}

// extractSelectorFromDomain extracts the selector from a DKIM lookup domain
// Example: "selector._domainkey.example.com" -> "selector"
func extractSelectorFromDomain(domain string) string {
	if parts := strings.SplitN(domain, "._domainkey.", 2); len(parts) == 2 {
		return parts[0]
	}
	return "unknown" // fallback if domain format is unexpected
}

// selectBestSignature selects the best signature for scoring purposes
func selectBestSignature(signatures []types.DKIMSignatureResult) *types.DKIMSignatureResult {
	if len(signatures) == 0 {
		return nil
	}

	var best *types.DKIMSignatureResult
	bestScore := -1.0

	for i := range signatures {
		sig := &signatures[i]
		score := scoreSignatureQuality(sig)

		if best == nil || score > bestScore {
			best = sig
			bestScore = score
		}
	}

	return best
}

// scoreSignatureQuality calculates a quality score for a signature
func scoreSignatureQuality(sig *types.DKIMSignatureResult) float64 {
	if sig == nil {
		return 0
	}

	score := 0.0

	// Valid signatures get base score
	if sig.Valid {
		score += 10.0
	}

	// Prefer stronger hash algorithms
	if !sig.WeakHash {
		score += 5.0
	}

	// Prefer signatures that include more headers
	score += float64(len(sig.Headers)) * 0.1

	// Prefer signatures with longer keys (when available)
	if sig.KeyLength >= 2048 {
		score += 2.0
	} else if sig.KeyLength >= 1024 {
		score += 1.0
	}

	// Prefer signatures without expiration (more stable)
	if sig.Expiration == 0 {
		score += 1.0
	}

	return score
}

// calculateEnhancedScore calculates the final DKIM score based on multiple signatures
func calculateEnhancedScore(result *types.DKIMResult) float64 {
	if result == nil || result.TotalSignatures == 0 {
		return 0
	}

	// Base score calculation
	var score float64

	// If we have valid signatures, start with negative score (good)
	if result.ValidSignatures > 0 {
		score = -1.0

		// Bonus for multiple valid signatures
		if result.ValidSignatures > 1 {
			score -= 0.5 * float64(result.ValidSignatures-1)
		}

		// Quality bonus from best signature
		if result.BestSignature != nil {
			qualityScore := scoreSignatureQuality(result.BestSignature)
			if qualityScore > 10 { // Only apply bonus for high-quality signatures
				score -= (qualityScore - 10) * 0.1
			}
		}
	} else {
		// No valid signatures - positive score (bad)
		score = 3.0

		// Penalty for weak hash signatures
		if result.WeakHash {
			score = 5.0
		}

		// Additional penalty for multiple failed signatures
		if result.TotalSignatures > 1 {
			score += 0.5 * float64(result.TotalSignatures-1)
		}
	}

	// Ensure score doesn't go below -5 or above 10
	if score < -5.0 {
		score = -5.0
	} else if score > 10.0 {
		score = 10.0
	}

	return score
}

// calculateEnhancedScoreWithDegradation calculates DKIM score with graceful degradation for partial failures
func calculateEnhancedScoreWithDegradation(result *types.DKIMResult) float64 {
	if result == nil || result.TotalSignatures == 0 {
		return 0
	}

	// Start with base enhanced score
	baseScore := calculateEnhancedScore(result)

	// Apply degradation adjustments based on edge cases and anomalies
	if result.EdgeCaseInfo != nil && len(result.EdgeCaseInfo.Anomalies) > 0 {
		// Adjust score based on threat level
		switch result.EdgeCaseInfo.ThreatLevel {
		case types.ThreatCritical:
			// Critical threats significantly increase spam score
			baseScore += 3.0
		case types.ThreatHigh:
			// High threats moderately increase spam score
			baseScore += 2.0
		case types.ThreatMedium:
			// Medium threats slightly increase spam score
			baseScore += 1.0
		case types.ThreatLow:
			// Low threats have minimal impact
			baseScore += 0.5
		}

		// Apply confidence-based adjustment
		confidenceAdjustment := (1.0 - result.EdgeCaseInfo.ConfidenceScore) * 0.5
		baseScore += confidenceAdjustment
	}

	// Apply graceful degradation for partial failures
	partialCreditScore := calculatePartialCreditScore(result)

	// Blend base score with partial credit score
	// If we have some valid signatures, partial credit can help
	if result.ValidSignatures > 0 {
		// Weight towards base score when we have valid signatures
		finalScore := (baseScore * 0.8) + (partialCreditScore * 0.2)
		return finalScore
	} else {
		// When no valid signatures, partial credit becomes more important
		finalScore := (baseScore * 0.6) + (partialCreditScore * 0.4)
		return finalScore
	}
}

// calculatePartialCreditScore calculates score based on partial information from failed signatures
func calculatePartialCreditScore(result *types.DKIMResult) float64 {
	if result == nil || len(result.Signatures) == 0 {
		return 0
	}

	partialScore := 0.0
	processedSignatures := 0

	for _, sig := range result.Signatures {
		if sig.Valid {
			continue // Skip valid signatures as they're handled in main scoring
		}

		// Award partial credit based on what information we could extract
		signatureCredit := 0.0

		// Credit for having a recognizable domain
		if sig.Domain != "" {
			signatureCredit += 0.1
		}

		// Credit for having headers signed (shows signing intent)
		if len(sig.Headers) > 0 {
			signatureCredit += 0.1 * float64(len(sig.Headers)) / 10.0 // Max 0.1 credit
		}

		// Credit for non-expired signatures
		if sig.Expiration == 0 || sig.Expiration > time.Now().Unix() {
			signatureCredit += 0.05
		}

		// Credit for strong key length (when available)
		if sig.KeyLength >= 2048 {
			signatureCredit += 0.05
		}

		// Penalty for weak hash algorithms
		if sig.WeakHash {
			signatureCredit -= 0.1
		}

		// Apply error-specific adjustments
		if sig.Error != "" {
			errorInfo := getErrorInfo(fmt.Errorf(sig.Error))
			if errorInfo != nil {
				switch errorInfo.Severity {
				case "low":
					signatureCredit += 0.05
				case "medium":
					// No adjustment
				case "high":
					signatureCredit -= 0.05
				case "critical":
					signatureCredit -= 0.1
				}
			}
		}

		partialScore += signatureCredit
		processedSignatures++
	}

	// Average the partial credit across processed signatures
	if processedSignatures > 0 {
		avgPartialCredit := partialScore / float64(processedSignatures)

		// Convert partial credit to score adjustment
		// Positive partial credit slightly reduces spam score
		// Negative partial credit increases spam score
		return -avgPartialCredit * 2.0 // Scale factor of 2
	}

	return 0
}

// VerifyForDMARC performs DKIM verification specifically for DMARC alignment checking
func VerifyForDMARC(rawEmail []byte, fromDomain string) (*types.DKIMResult, error) {
	result, err := VerifyWithCorrelationID(rawEmail, "")
	if err != nil {
		return nil, err
	}

	// Update alignment candidates with DMARC-specific information
	for i := range result.AlignmentCandidates {
		candidate := &result.AlignmentCandidates[i]

		// Determine alignment mode and result
		if strings.EqualFold(candidate.Domain, fromDomain) {
			candidate.AlignmentMode = "strict"
			candidate.AlignmentResult = "pass"
		} else if isDomainAligned(candidate.Domain, fromDomain, false) {
			candidate.AlignmentMode = "relaxed"
			candidate.AlignmentResult = "pass"
		} else {
			candidate.AlignmentMode = "relaxed"
			candidate.AlignmentResult = "fail"
		}
	}

	return result, nil
}

// isDomainAligned checks if two domains are aligned according to DMARC rules
func isDomainAligned(sigDomain, fromDomain string, strict bool) bool {
	if strict {
		return strings.EqualFold(sigDomain, fromDomain)
	}

	// Relaxed alignment: organizational domains must match
	sigOrgDomain := getOrganizationalDomain(sigDomain)
	fromOrgDomain := getOrganizationalDomain(fromDomain)

	return strings.EqualFold(sigOrgDomain, fromOrgDomain)
}

// getOrganizationalDomain extracts the organizational domain (simplified implementation)
func getOrganizationalDomain(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return domain
	}

	// For this simplified implementation, just return the last two parts
	// In production, this should use the Public Suffix List
	return strings.Join(parts[len(parts)-2:], ".")
}

// GetOrganizationalDomainDetailed extracts organizational domain with detailed information
func GetOrganizationalDomainDetailed(domain string) *types.OrganizationalDomain {
	if domain == "" {
		return nil
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	parts := strings.Split(domain, ".")

	if len(parts) < 2 {
		return &types.OrganizationalDomain{
			Domain:         domain,
			OrgDomain:      domain,
			PublicSuffix:   domain,
			Subdomain:      "",
			IsPublicSuffix: true,
		}
	}

	// Simplified public suffix detection
	// In production, this should use the Mozilla Public Suffix List
	publicSuffixes := map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		"mil": true, "int": true, "co.uk": true, "ac.uk": true, "gov.uk": true,
		"com.au": true, "net.au": true, "org.au": true, "edu.au": true,
		"co.jp": true, "ac.jp": true, "go.jp": true, "or.jp": true,
		"de": true, "fr": true, "it": true, "es": true, "nl": true, "be": true,
		"ch": true, "at": true, "se": true, "no": true, "dk": true, "fi": true,
		"br": true, "mx": true, "ar": true, "cl": true, "pe": true, "co": true,
		"ca": true, "us": true, "ru": true, "cn": true, "in": true, "kr": true,
	}

	var publicSuffix string
	var orgDomain string
	var subdomain string

	// Check for multi-part public suffixes first (like co.uk)
	if len(parts) >= 2 {
		twoPartSuffix := strings.Join(parts[len(parts)-2:], ".")
		if publicSuffixes[twoPartSuffix] {
			publicSuffix = twoPartSuffix
			if len(parts) >= 3 {
				orgDomain = strings.Join(parts[len(parts)-3:], ".")
				if len(parts) > 3 {
					subdomain = strings.Join(parts[:len(parts)-3], ".")
				}
			} else {
				orgDomain = domain
			}
		}
	}

	// If no two-part suffix found, check single-part
	if publicSuffix == "" {
		lastPart := parts[len(parts)-1]
		if publicSuffixes[lastPart] || len(lastPart) == 2 { // Assume 2-letter TLDs
			publicSuffix = lastPart
			if len(parts) >= 2 {
				orgDomain = strings.Join(parts[len(parts)-2:], ".")
				if len(parts) > 2 {
					subdomain = strings.Join(parts[:len(parts)-2], ".")
				}
			} else {
				orgDomain = domain
			}
		} else {
			// Unknown TLD, treat as org domain
			publicSuffix = lastPart
			orgDomain = domain
		}
	}

	return &types.OrganizationalDomain{
		Domain:         domain,
		OrgDomain:      orgDomain,
		PublicSuffix:   publicSuffix,
		Subdomain:      subdomain,
		IsPublicSuffix: len(parts) == 1 || (len(parts) == 2 && publicSuffixes[domain]),
	}
}

// CheckDMARCAlignment performs DMARC alignment checking for DKIM
func CheckDMARCAlignment(fromDomain string, dkimResult *types.DKIMResult, alignmentMode types.DMARCAlignmentMode) bool {
	if dkimResult == nil || !dkimResult.Valid || fromDomain == "" {
		return false
	}

	// Use the primary domain from DKIM result
	signingDomain := dkimResult.Domain
	if signingDomain == "" {
		return false
	}

	// Perform alignment check based on mode
	switch alignmentMode {
	case types.AlignmentStrict:
		// Strict alignment: domains must match exactly
		return strings.EqualFold(signingDomain, fromDomain)

	case types.AlignmentRelaxed:
		// Relaxed alignment: organizational domains must match
		fromOrgDomain := GetOrganizationalDomainDetailed(fromDomain)
		sigOrgDomain := GetOrganizationalDomainDetailed(signingDomain)

		if fromOrgDomain == nil || sigOrgDomain == nil {
			return false
		}

		return strings.EqualFold(fromOrgDomain.OrgDomain, sigOrgDomain.OrgDomain)

	default:
		// Default to relaxed alignment
		return CheckDMARCAlignment(fromDomain, dkimResult, types.AlignmentRelaxed)
	}
}

// detectEdgeCases analyzes DKIM signatures for anomalies and edge cases
func detectEdgeCases(signatures []types.DKIMSignatureResult) *types.DKIMEdgeCaseInfo {
	if len(signatures) == 0 {
		return nil
	}

	edgeCaseInfo := &types.DKIMEdgeCaseInfo{
		Anomalies:         make([]types.DKIMAnomalyFlag, 0),
		ThreatLevel:       types.ThreatNone,
		ThreatDescription: "",
		RecommendedAction: "none",
		ConfidenceScore:   0.8, // Default confidence
	}

	// Analyze signatures for various anomalies
	analyzeDomainConsistency(signatures, edgeCaseInfo)
	analyzeHashAlgorithms(signatures, edgeCaseInfo)
	analyzeSignatureTiming(signatures, edgeCaseInfo)
	analyzeSignatureCount(signatures, edgeCaseInfo)
	analyzeKeyStrength(signatures, edgeCaseInfo)
	analyzeSelectorConsistency(signatures, edgeCaseInfo)
	analyzeHeaderCoverage(signatures, edgeCaseInfo)

	// Assess overall threat level
	assessThreatLevel(edgeCaseInfo)

	return edgeCaseInfo
}

// analyzeDomainConsistency checks for domain-related anomalies
func analyzeDomainConsistency(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	validDomains := make(map[string]bool)
	allDomains := make(map[string]bool)

	for _, sig := range signatures {
		allDomains[sig.Domain] = true
		if sig.Valid {
			validDomains[sig.Domain] = true
		}
	}

	// Check for multiple valid domains
	if len(validDomains) > 1 {
		info.Anomalies = append(info.Anomalies, types.AnomalyMultipleValidDomains)
	}

	// Check for domain mismatch patterns
	if len(allDomains) > 2 {
		info.Anomalies = append(info.Anomalies, types.AnomalyDomainMismatch)
	}
}

// analyzeHashAlgorithms checks for hash algorithm anomalies
func analyzeHashAlgorithms(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	hashAlgorithms := make(map[string]int)
	weakHashCount := 0

	for _, sig := range signatures {
		hashAlgorithms[sig.HashAlgorithm]++
		if sig.WeakHash {
			weakHashCount++
		}
	}

	// Check for mixed hash algorithms
	if len(hashAlgorithms) > 1 {
		info.Anomalies = append(info.Anomalies, types.AnomalyMixedHashAlgorithms)
	}
}

// analyzeSignatureTiming checks for timing-related anomalies
func analyzeSignatureTiming(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	now := time.Now().Unix()
	expiredCount := 0
	futureCount := 0

	for _, sig := range signatures {
		// Check for expired signatures
		if sig.Expiration > 0 && sig.Expiration < now {
			expiredCount++
		}

		// Check for future signatures (more than 5 minutes in the future)
		if sig.Timestamp > now+300 {
			futureCount++
		}
	}

	if expiredCount > 0 {
		info.Anomalies = append(info.Anomalies, types.AnomalyExpiredSignatures)
	}

	if futureCount > 0 {
		info.Anomalies = append(info.Anomalies, types.AnomalyFutureSignatures)
	}
}

// analyzeSignatureCount checks for signature count anomalies
func analyzeSignatureCount(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	// Flag if there are too many signatures (potential DoS or confusion attack)
	if len(signatures) > 10 {
		info.Anomalies = append(info.Anomalies, types.AnomalyTooManySignatures)
	}

	// Check for signature rollover patterns (multiple signatures from same domain)
	domainSigCount := make(map[string]int)
	for _, sig := range signatures {
		domainSigCount[sig.Domain]++
	}

	for _, count := range domainSigCount {
		if count > 2 {
			info.Anomalies = append(info.Anomalies, types.AnomalySignatureRollover)
			break
		}
	}
}

// analyzeKeyStrength checks for weak key strength
func analyzeKeyStrength(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	for _, sig := range signatures {
		if sig.KeyLength > 0 && sig.KeyLength < 2048 {
			info.Anomalies = append(info.Anomalies, types.AnomalyWeakKeyLength)
			break
		}
	}
}

// analyzeSelectorConsistency checks for selector-related anomalies
func analyzeSelectorConsistency(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	selectors := make(map[string]bool)
	for _, sig := range signatures {
		if sig.Selector != "" {
			selectors[sig.Selector] = true
		}
	}

	// Flag if there are many different selectors (potential confusion)
	if len(selectors) > 3 {
		info.Anomalies = append(info.Anomalies, types.AnomalyInconsistentSelectors)
	}
}

// analyzeHeaderCoverage checks for suspicious header coverage patterns
func analyzeHeaderCoverage(signatures []types.DKIMSignatureResult, info *types.DKIMEdgeCaseInfo) {
	for _, sig := range signatures {
		headerCount := len(sig.Headers)
		// Flag signatures with unusually few or many headers
		if headerCount < 2 || headerCount > 50 {
			info.Anomalies = append(info.Anomalies, types.AnomalySuspiciousHeaderCount)
			break
		}
	}
}

// assessThreatLevel determines the overall threat level based on detected anomalies
func assessThreatLevel(info *types.DKIMEdgeCaseInfo) {
	if len(info.Anomalies) == 0 {
		info.ThreatLevel = types.ThreatNone
		info.ThreatDescription = "No anomalies detected"
		info.RecommendedAction = "none"
		return
	}

	// Calculate threat score based on anomaly types
	threatScore := 0
	criticalAnomalies := []string{}
	highRiskAnomalies := []string{}

	for _, anomaly := range info.Anomalies {
		switch anomaly {
		case types.AnomalyTooManySignatures, types.AnomalyFutureSignatures:
			threatScore += 4
			criticalAnomalies = append(criticalAnomalies, string(anomaly))
		case types.AnomalyDomainMismatch, types.AnomalyWeakKeyLength:
			threatScore += 3
			highRiskAnomalies = append(highRiskAnomalies, string(anomaly))
		case types.AnomalyMixedHashAlgorithms, types.AnomalyExpiredSignatures:
			threatScore += 2
		default:
			threatScore += 1
		}
	}

	// Determine threat level and recommendations
	if threatScore >= 8 {
		info.ThreatLevel = types.ThreatCritical
		info.ThreatDescription = fmt.Sprintf("Critical anomalies detected: %s", strings.Join(criticalAnomalies, ", "))
		info.RecommendedAction = "reject"
	} else if threatScore >= 5 {
		info.ThreatLevel = types.ThreatHigh
		info.ThreatDescription = fmt.Sprintf("High-risk anomalies detected: %s", strings.Join(highRiskAnomalies, ", "))
		info.RecommendedAction = "quarantine"
	} else if threatScore >= 3 {
		info.ThreatLevel = types.ThreatMedium
		info.ThreatDescription = fmt.Sprintf("Multiple anomalies detected (%d)", len(info.Anomalies))
		info.RecommendedAction = "flag_for_review"
	} else {
		info.ThreatLevel = types.ThreatLow
		info.ThreatDescription = fmt.Sprintf("Minor anomalies detected (%d)", len(info.Anomalies))
		info.RecommendedAction = "monitor"
	}

	// Adjust confidence based on number of signatures analyzed
	if len(info.Anomalies) > 3 {
		info.ConfidenceScore = 0.9
	} else if len(info.Anomalies) > 1 {
		info.ConfidenceScore = 0.85
	} else {
		info.ConfidenceScore = 0.75
	}
}

// handleSignatureError implements graceful degradation for different error types
func handleSignatureError(err error, sigResult *types.DKIMSignatureResult, result *types.DKIMResult, errorInfo *DKIMErrorInfo) {
	if errorInfo == nil {
		return
	}

	// Handle specific error categories with appropriate degradation
	switch errorInfo.Category {
	case "algorithm":
		// For algorithm issues, check if it's specifically weak hash
		if strings.Contains(err.Error(), "hash algorithm too weak") {
			sigResult.WeakHash = true
			result.WeakHash = true
			// Still count as partial validation for scoring purposes
			sigResult.Algorithm = "rsa-sha1" // Mark as weak algorithm
			sigResult.HashAlgorithm = "sha1"
		}

	case "timing":
		// For expired signatures, still extract useful information
		if strings.Contains(err.Error(), "signature has expired") {
			// Signature was valid at some point, so it has some trust value
			// This helps with forensic analysis
		}

	case "key_lookup":
		// For key lookup failures, this might be temporary
		// Don't completely invalidate if we have other valid signatures
		if strings.Contains(err.Error(), "key unavailable") {
			// Mark as temporary failure rather than permanent invalidity
		}

	case "verification":
		// For verification failures, these are critical
		// But still preserve the signature info for analysis
		if strings.Contains(err.Error(), "body hash did not verify") {
			// This indicates potential message tampering
		} else if strings.Contains(err.Error(), "signature did not verify") {
			// This indicates potential header tampering or key mismatch
		}

	case "headers":
		// For header issues, signature might still provide some value
		if strings.Contains(err.Error(), "From field not signed") {
			// This is a policy violation but signature itself might be valid
		}

	default:
		// For unknown errors, apply conservative degradation
	}

	// Apply graceful degradation scoring
	applyGracefulDegradation(sigResult, errorInfo)
}

// applyGracefulDegradation adjusts signature scoring for partial failures
func applyGracefulDegradation(sigResult *types.DKIMSignatureResult, errorInfo *DKIMErrorInfo) {
	if errorInfo == nil {
		return
	}

	// Assign partial credit based on error severity and category
	switch errorInfo.Severity {
	case "low":
		// Low severity errors get most of the credit
		// These are often configuration or policy issues
	case "medium":
		// Medium severity errors get some credit
		// These indicate potential issues but not critical failures
	case "high":
		// High severity errors get minimal credit
		// These are significant problems
	case "critical":
		// Critical errors get no credit
		// These indicate tampering or major failures
	default:
		// Unknown severity treated as medium
	}

	// Store error context for downstream processing
	// This allows other systems to make informed decisions
	// about how to handle partial failures
}
