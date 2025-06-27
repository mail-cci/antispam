package dmarc

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"

	"github.com/mail-cci/antispam/internal/types"
)

// DMARCVerifier handles DMARC policy verification
type DMARCVerifier struct {
	logger    *zap.Logger
	rdb       *redis.Client
	resolver  *net.Resolver
	cacheEnabled bool
	cacheTTL  time.Duration
}

// Config holds DMARC configuration
type Config struct {
	Enabled     bool          `yaml:"enabled" default:"true"`
	Timeout     time.Duration `yaml:"timeout" default:"10s"`
	CacheTTL    time.Duration `yaml:"cache_ttl" default:"4h"`
	MaxRetries  int           `yaml:"max_retries" default:"3"`
	
	// Scoring configuration
	Scoring struct {
		Pass             float64 `yaml:"pass" default:"-2.0"`
		Fail             float64 `yaml:"fail" default:"5.0"`
		NoPolicy         float64 `yaml:"no_policy" default:"0.5"`
		AlignmentFailure float64 `yaml:"alignment_failure" default:"3.0"`
		PolicyViolation  float64 `yaml:"policy_violation" default:"4.0"`
	} `yaml:"scoring"`
}

// NewVerifier creates a new DMARC verifier
func NewVerifier(logger *zap.Logger, rdb *redis.Client, config *Config) *DMARCVerifier {
	return &DMARCVerifier{
		logger:       logger,
		rdb:          rdb,
		resolver:     &net.Resolver{},
		cacheEnabled: rdb != nil,
		cacheTTL:     config.CacheTTL,
	}
}

// Verify performs complete DMARC verification
func (v *DMARCVerifier) Verify(ctx context.Context, fromDomain string, spfResult *types.SPFResult, dkimResult *types.DKIMResult) (*types.DMARCResult, error) {
	if v.logger != nil {
		v.logger.Debug("Starting DMARC verification",
			zap.String("from_domain", fromDomain))
	}

	result := &types.DMARCResult{
		Valid:       false,
		Disposition: "none",
		Reason:      make([]string, 0),
		Score:       0.0,
	}

	// Step 1: Extract organizational domain
	orgDomain := v.getOrganizationalDomain(fromDomain)
	if orgDomain == "" {
		result.Error = "failed to extract organizational domain"
		return result, fmt.Errorf("invalid domain: %s", fromDomain)
	}

	// Step 2: Query DMARC policy
	policy, err := v.queryPolicy(ctx, orgDomain)
	if err != nil {
		if v.logger != nil {
			v.logger.Debug("DMARC policy query failed",
				zap.String("domain", orgDomain),
				zap.Error(err))
		}
		result.Error = fmt.Sprintf("policy query failed: %v", err)
		result.Score = 0.5 // Small penalty for no policy
		return result, nil // Not a hard error
	}

	if policy == nil {
		result.Error = "no DMARC policy found"
		result.Score = 0.5
		return result, nil
	}

	result.Policy = policy

	// Step 3: Check SPF and DKIM alignment
	alignment := v.checkAlignment(fromDomain, spfResult, dkimResult, policy)
	result.Alignment = alignment

	// Step 4: Apply DMARC policy
	disposition, reasons := v.applyPolicy(policy, alignment)
	result.Disposition = disposition
	result.Reason = reasons

	// Step 5: Calculate final result
	result.Valid = (alignment.SPFAligned || alignment.DKIMAligned)
	result.Score = v.calculateScore(result, policy, alignment)

	if v.logger != nil {
		v.logger.Debug("DMARC verification completed",
			zap.String("domain", fromDomain),
			zap.Bool("valid", result.Valid),
			zap.String("disposition", result.Disposition),
			zap.Float64("score", result.Score))
	}

	return result, nil
}

// queryPolicy retrieves DMARC policy from DNS
func (v *DMARCVerifier) queryPolicy(ctx context.Context, domain string) (*types.DMARCPolicy, error) {
	// Try cache first
	if v.cacheEnabled {
		if cached := v.getCachedPolicy(ctx, domain); cached != nil {
			return cached, nil
		}
	}

	// Query DNS
	dmarcDomain := "_dmarc." + domain
	
	if v.logger != nil {
		v.logger.Debug("Querying DMARC DNS record",
			zap.String("domain", dmarcDomain))
	}

	txtRecords, err := v.resolver.LookupTXT(ctx, dmarcDomain)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %w", err)
	}

	// Find DMARC record
	var dmarcRecord string
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		return nil, fmt.Errorf("no DMARC record found")
	}

	// Parse DMARC record
	policy := v.parseDMARCRecord(dmarcRecord)
	policy.Domain = domain
	policy.TTL = 3600 // Default TTL

	// Cache the result
	if v.cacheEnabled {
		v.cachePolicy(ctx, domain, policy)
	}

	return policy, nil
}

// parseDMARCRecord parses a DMARC TXT record
func (v *DMARCVerifier) parseDMARCRecord(record string) *types.DMARCPolicy {
	policy := &types.DMARCPolicy{
		Policy:          "none",
		SubdomainPolicy: "",
		SPFAlignment:    types.AlignmentRelaxed,
		DKIMAlignment:   types.AlignmentRelaxed,
		Percentage:      100,
		ReportURI:       make([]string, 0),
		ForensicURI:     make([]string, 0),
	}

	// Split record into tag-value pairs
	pairs := strings.Split(record, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			continue
		}

		tag := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToLower(tag) {
		case "v":
			// Version - already validated
		case "p":
			policy.Policy = strings.ToLower(value)
		case "sp":
			policy.SubdomainPolicy = strings.ToLower(value)
		case "adkim":
			if strings.ToLower(value) == "s" {
				policy.DKIMAlignment = types.AlignmentStrict
			} else {
				policy.DKIMAlignment = types.AlignmentRelaxed
			}
		case "aspf":
			if strings.ToLower(value) == "s" {
				policy.SPFAlignment = types.AlignmentStrict
			} else {
				policy.SPFAlignment = types.AlignmentRelaxed
			}
		case "pct":
			if pct, err := strconv.Atoi(value); err == nil && pct >= 0 && pct <= 100 {
				policy.Percentage = pct
			}
		case "rua":
			policy.ReportURI = strings.Split(value, ",")
		case "ruf":
			policy.ForensicURI = strings.Split(value, ",")
		}
	}

	return policy
}

// checkAlignment verifies SPF and DKIM alignment
func (v *DMARCVerifier) checkAlignment(fromDomain string, spfResult *types.SPFResult, dkimResult *types.DKIMResult, policy *types.DMARCPolicy) *types.DMARCAlignmentResult {
	alignment := &types.DMARCAlignmentResult{
		FromDomain: fromDomain,
		SPFMode:    policy.SPFAlignment,
		DKIMMode:   policy.DKIMAlignment,
	}

	// Check SPF alignment
	if spfResult != nil && spfResult.Result == "pass" {
		alignment.SPFDomain = spfResult.Domain
		alignment.SPFAligned = v.checkDomainAlignment(fromDomain, spfResult.Domain, policy.SPFAlignment)
	}

	// Check DKIM alignment
	if dkimResult != nil && dkimResult.Valid {
		// Find best aligned DKIM signature
		for _, candidate := range dkimResult.AlignmentCandidates {
			if candidate.Valid {
				alignment.DKIMDomain = candidate.Domain
				if v.checkDomainAlignment(fromDomain, candidate.Domain, policy.DKIMAlignment) {
					alignment.DKIMAligned = true
					break
				}
			}
		}
	}

	return alignment
}

// checkDomainAlignment checks if two domains are aligned according to the specified mode
func (v *DMARCVerifier) checkDomainAlignment(fromDomain, authDomain string, mode types.DMARCAlignmentMode) bool {
	if strings.EqualFold(fromDomain, authDomain) {
		return true // Exact match always passes
	}

	if mode == types.AlignmentStrict {
		return false // Strict mode requires exact match
	}

	// Relaxed mode - check organizational domains
	fromOrg := v.getOrganizationalDomain(fromDomain)
	authOrg := v.getOrganizationalDomain(authDomain)
	
	return strings.EqualFold(fromOrg, authOrg)
}

// applyPolicy determines the final disposition based on policy and alignment
func (v *DMARCVerifier) applyPolicy(policy *types.DMARCPolicy, alignment *types.DMARCAlignmentResult) (string, []string) {
	reasons := make([]string, 0)

	// Check if either SPF or DKIM is aligned
	if alignment.SPFAligned || alignment.DKIMAligned {
		return "none", reasons // DMARC passes
	}

	// DMARC failed - apply policy
	disposition := policy.Policy
	
	// Add reasons for failure
	if !alignment.SPFAligned {
		if alignment.SPFDomain != "" {
			reasons = append(reasons, "SPF alignment failed")
		} else {
			reasons = append(reasons, "SPF check failed")
		}
	}
	
	if !alignment.DKIMAligned {
		if alignment.DKIMDomain != "" {
			reasons = append(reasons, "DKIM alignment failed")
		} else {
			reasons = append(reasons, "DKIM check failed")
		}
	}

	// Apply percentage
	if policy.Percentage < 100 {
		// In a real implementation, you'd use a deterministic random function
		// For now, we apply the policy fully
		reasons = append(reasons, fmt.Sprintf("policy percentage: %d%%", policy.Percentage))
	}

	return disposition, reasons
}

// calculateScore calculates the DMARC contribution to spam score
func (v *DMARCVerifier) calculateScore(result *types.DMARCResult, policy *types.DMARCPolicy, alignment *types.DMARCAlignmentResult) float64 {
	// Default scoring configuration
	config := struct {
		Pass             float64
		Fail             float64
		NoPolicy         float64
		AlignmentFailure float64
		PolicyViolation  float64
	}{
		Pass:             -2.0,
		Fail:             5.0,
		NoPolicy:         0.5,
		AlignmentFailure: 3.0,
		PolicyViolation:  4.0,
	}

	if policy == nil {
		return config.NoPolicy
	}

	if result.Valid {
		return config.Pass // DMARC passes - negative score is good
	}

	// DMARC failed - determine penalty based on policy
	baseScore := config.Fail

	switch policy.Policy {
	case "reject":
		baseScore += config.PolicyViolation
	case "quarantine":
		baseScore += config.PolicyViolation * 0.5
	case "none":
		baseScore = config.AlignmentFailure // Less severe for monitoring-only
	}

	return baseScore
}

// getOrganizationalDomain extracts the organizational domain
func (v *DMARCVerifier) getOrganizationalDomain(domain string) string {
	orgDomain, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// Fallback - return the domain as-is
		return domain
	}
	return orgDomain
}

// Cache management functions
func (v *DMARCVerifier) getCachedPolicy(ctx context.Context, domain string) *types.DMARCPolicy {
	if !v.cacheEnabled {
		return nil
	}

	key := fmt.Sprintf("dmarc:policy:%s", domain)
	result, err := v.rdb.Get(ctx, key).Result()
	if err != nil {
		return nil
	}

	// In a real implementation, you'd deserialize the policy from JSON/protobuf
	// For now, return nil to force DNS lookup
	_ = result
	return nil
}

func (v *DMARCVerifier) cachePolicy(ctx context.Context, domain string, policy *types.DMARCPolicy) {
	if !v.cacheEnabled {
		return
	}

	key := fmt.Sprintf("dmarc:policy:%s", domain)
	// In a real implementation, you'd serialize the policy to JSON/protobuf
	_ = v.rdb.Set(ctx, key, "cached", v.cacheTTL)
}