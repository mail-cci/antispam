package dkim

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
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
	cfg    *config.Config
	rdb    *redis.Client
	logger *zap.Logger
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

var dkimErrorMap = map[string]int{
	"empty selector":                                DKIM_SIGERROR_EMPTY_S,
	"invalid selector":                              DKIM_SIGERROR_EMPTY_S,
	"s tag not found":                               DKIM_SIGERROR_EMPTY_S,
	"incompatible signature version":                DKIM_SIGERROR_VERSION,
	"signature has expired":                         DKIM_SIGERROR_EXPIRED,
	"no valid key found":                            DKIM_SIGERROR_NOREC,
	"key unavailable":                               DKIM_SIGERROR_KEYFAIL,
	"no key for signature":                          DKIM_SIGERROR_NOKEY,
	"multiple TXT records found for key":            DKIM_SIGERROR_KEYFAIL,
	"unsupported header canonicalization algorithm": DKIM_SIGERROR_INVALID_HC,
	"unsupported body canonicalization algorithm":   DKIM_SIGERROR_INVALID_BC,
	"malformed algorithm name":                      DKIM_SIGERROR_INVALID_A,
	"unsupported key algorithm":                     DKIM_SIGERROR_INVALID_A,
	"inappropriate key algorithm":                   DKIM_SIGERROR_INVALID_A,
	"inappropriate hash algorithm":                  DKIM_SIGERROR_INVALID_A,
	"hash algorithm too weak":                       DKIM_SIGERROR_INVALID_A,
	"unsupported hash algorithm":                    DKIM_SIGERROR_INVALID_A,
	"message contains an insecure body length tag":  DKIM_SIGERROR_INVALID_L,
	"malformed body hash":                           DKIM_SIGERROR_EMPTY_BH,
	"malformed signature":                           DKIM_SIGERROR_EMPTY_B,
	"body hash did not verify":                      DKIM_SIGERROR_BADSIG,
	"signature did not verify":                      DKIM_SIGERROR_BADSIG,
	"From field not signed":                         DKIM_SIGERROR_INVALID_H,
	"domain mismatch":                               DKIM_SIGERROR_EMPTY_D,
	"incompatible public key version":               DKIM_SIGERROR_VERSION,
	"unsupported public key query method":           DKIM_SIGERROR_UNKNOWN,
}

func errorCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	msg := err.Error()
	for substr, code := range dkimErrorMap {
		if strings.Contains(msg, substr) {
			return code
		}
	}
	return DKIM_SIGERROR_UNKNOWN
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
	res := &types.DKIMResult{}

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

	// Parse headers to extract selectors from DKIM or ARC signatures
	if msg, err := mail.ReadMessage(bytes.NewReader(rawEmail)); err == nil {
		if logger != nil {
			logger.Debug("email parsed successfully", addCorrelationID([]zap.Field{
				zap.String("step", "parse_headers"),
			}, correlationID)...)
		}

		process := func(headerType string, values []string) {
			if logger != nil {
				logger.Debug("processing headers", addCorrelationID([]zap.Field{
					zap.String("step", "process_headers"),
					zap.String("header_type", headerType),
					zap.Int("header_count", len(values)),
				}, correlationID)...)
			}

			for i, v := range values {
				if logger != nil {
					logger.Debug("processing signature header", addCorrelationID([]zap.Field{
						zap.String("step", "parse_signature"),
						zap.String("header_type", headerType),
						zap.Int("signature_index", i),
						zap.String("signature_preview", truncateString(v, 100)),
					}, correlationID)...)
				}

				sel, err := parseSelector(v)
				if err != nil {
					if logger != nil {
						logger.Debug("selector parsing failed", addCorrelationID([]zap.Field{
							zap.String("step", "parse_selector"),
							zap.Int("error_code", errorCodeFromError(err)),
							zap.Error(err),
							zap.String("signature_preview", truncateString(v, 100)),
						}, correlationID)...)
					}
					continue
				}

				if logger != nil {
					logger.Debug("selector extracted successfully", addCorrelationID([]zap.Field{
						zap.String("step", "extract_selector"),
						zap.String("selector", sel),
					}, correlationID)...)
				}

				if res.Selector == "" {
					res.Selector = sel
				}
			}
		}

		dkHeader := textproto.CanonicalMIMEHeaderKey("DKIM-Signature")
		arcHeader := textproto.CanonicalMIMEHeaderKey("ARC-Message-Signature")

		dkimHeaders := msg.Header[dkHeader]
		arcHeaders := msg.Header[arcHeader]

		if logger != nil {
			logger.Debug("found signature headers", addCorrelationID([]zap.Field{
				zap.String("step", "count_headers"),
				zap.Int("dkim_signatures", len(dkimHeaders)),
				zap.Int("arc_signatures", len(arcHeaders)),
			}, correlationID)...)
		}

		process("DKIM-Signature", dkimHeaders)
		process("ARC-Message-Signature", arcHeaders)
	} else {
		if logger != nil {
			logger.Debug("failed to parse email headers",
				zap.String("step", "parse_headers"),
				zap.Error(err))
		}
	}

	start := time.Now()
	metrics.DKIMChecksTotal.Inc()

	if logger != nil {
		logger.Debug("setup verification context",
			zap.String("step", "setup_context"))
	}

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

	for i, v := range verifs {
		if logger != nil {
			logger.Debug("processing verification result",
				zap.String("step", "process_result"),
				zap.Int("result_index", i),
				zap.String("domain", v.Domain),
				zap.Error(v.Err))
		}

		if res.Domain == "" {
			res.Domain = v.Domain
		}
		if v.Err == nil {
			res.Valid = true
			if logger != nil {
				logger.Debug("valid DKIM signature found",
					zap.String("step", "valid_signature"),
					zap.String("domain", v.Domain))
			}
		} else if logger != nil {
			logger.Debug("DKIM signature validation failed",
				zap.String("step", "signature_failed"),
				zap.String("domain", v.Domain),
				zap.Int("error_code", errorCodeFromError(v.Err)),
				zap.Error(v.Err))
		}
	}

	res.Score = scoreFor(res.Valid)
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
