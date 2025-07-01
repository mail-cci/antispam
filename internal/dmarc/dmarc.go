package dmarc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

	// Step 2: Query DMARC policy (with subdomain fallback)
	policy, err := v.queryPolicyWithSubdomain(ctx, fromDomain, orgDomain)
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

	// Step 6: Generate report information
	result.ReportInfo = v.generateReportInfo(fromDomain, spfResult, dkimResult, result)

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

// parseDMARCRecord parses a DMARC TXT record using the robust parser
func (v *DMARCVerifier) parseDMARCRecord(record string) *types.DMARCPolicy {
	// Create parser instance
	parser := NewParser(v.logger)
	
	// Use robust parser with comprehensive validation
	policy, err := parser.ParseDMARCRecord(record)
	if err != nil {
		if v.logger != nil {
			v.logger.Error("Failed to parse DMARC record with robust parser",
				zap.String("record", record),
				zap.Error(err))
		}
		
		// Fallback to basic policy with error information
		return &types.DMARCPolicy{
			Policy:          "none",
			SubdomainPolicy: "",
			SPFAlignment:    types.AlignmentRelaxed,
			DKIMAlignment:   types.AlignmentRelaxed,
			Percentage:      100,
			ReportURI:       make([]string, 0),
			ForensicURI:     make([]string, 0),
			RawRecord:       record,
			ParseErrors:     []string{err.Error()},
			UnknownTags:     make(map[string]string),
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
		if v.logger != nil {
			v.logger.Debug("DMARC policy cache miss",
				zap.String("domain", domain),
				zap.Error(err))
		}
		return nil
	}

	// Deserialize policy from JSON
	var policy types.DMARCPolicy
	if err := json.Unmarshal([]byte(result), &policy); err != nil {
		if v.logger != nil {
			v.logger.Error("Failed to deserialize cached DMARC policy",
				zap.String("domain", domain),
				zap.Error(err))
		}
		return nil
	}

	if v.logger != nil {
		v.logger.Debug("DMARC policy cache hit",
			zap.String("domain", domain),
			zap.String("policy", policy.Policy))
	}

	return &policy
}

func (v *DMARCVerifier) cachePolicy(ctx context.Context, domain string, policy *types.DMARCPolicy) {
	if !v.cacheEnabled || policy == nil {
		return
	}

	key := fmt.Sprintf("dmarc:policy:%s", domain)
	
	// Serialize policy to JSON
	data, err := json.Marshal(policy)
	if err != nil {
		if v.logger != nil {
			v.logger.Error("Failed to serialize DMARC policy for caching",
				zap.String("domain", domain),
				zap.Error(err))
		}
		return
	}

	// Calculate TTL based on DNS record TTL or default
	cacheTTL := v.cacheTTL
	if policy.TTL > 0 {
		dnsTTL := time.Duration(policy.TTL) * time.Second
		if dnsTTL < cacheTTL {
			cacheTTL = dnsTTL
		}
	}

	if err := v.rdb.Set(ctx, key, string(data), cacheTTL).Err(); err != nil {
		if v.logger != nil {
			v.logger.Error("Failed to cache DMARC policy",
				zap.String("domain", domain),
				zap.Error(err))
		}
		return
	}

	if v.logger != nil {
		v.logger.Debug("DMARC policy cached successfully",
			zap.String("domain", domain),
			zap.Duration("ttl", cacheTTL))
	}
}

// generateReportInfo creates report information for DMARC feedback
func (v *DMARCVerifier) generateReportInfo(fromDomain string, spfResult *types.SPFResult, dkimResult *types.DKIMResult, dmarcResult *types.DMARCResult) *types.DMARCReportInfo {
	reportInfo := &types.DMARCReportInfo{
		MessageDate:     time.Now().Unix(),
		HeaderFrom:      fromDomain,
		PolicyDomain:    fromDomain,
		Disposition:     dmarcResult.Disposition,
		ReportGenerated: false,
	}

	// Set SPF information
	if spfResult != nil {
		reportInfo.SPFResult = spfResult.Result
		reportInfo.SPFDomain = spfResult.Domain
	} else {
		reportInfo.SPFResult = "none"
	}

	// Set DKIM information
	if dkimResult != nil {
		if dkimResult.Valid {
			reportInfo.DKIMResult = "pass"
		} else {
			reportInfo.DKIMResult = "fail"
		}
		reportInfo.DKIMDomain = dkimResult.Domain
	} else {
		reportInfo.DKIMResult = "none"
	}

	// Determine if report should be generated
	// Generate reports for failures or when policy requires it
	if dmarcResult.Policy != nil {
		// Generate report if DMARC failed or if policy has reporting URIs
		reportInfo.ReportGenerated = (!dmarcResult.Valid || len(dmarcResult.Policy.ReportURI) > 0)
	}

	return reportInfo
}

// generateForensicReport creates a forensic report for DMARC failures
func (v *DMARCVerifier) generateForensicReport(messageID, sourceIP, originalMessage string, dmarcResult *types.DMARCResult) *types.DMARCForensicReport {
	if dmarcResult.Valid || dmarcResult.Policy == nil || len(dmarcResult.Policy.ForensicURI) == 0 {
		return nil // No forensic report needed
	}

	report := &types.DMARCForensicReport{
		MessageID:       messageID,
		ReportID:        fmt.Sprintf("dmarc-forensic-%d", time.Now().Unix()),
		FeedbackType:    "auth-failure",
		UserAgent:       "CCI-Antispam-DMARC/1.0",
		Version:         "1.0",
		OriginalDate:    time.Now().Unix(),
		ArrivalDate:     time.Now().Unix(),
		SourceIP:        sourceIP,
		DeliveryResult:  dmarcResult.Disposition,
		OriginalMessage: originalMessage,
		ReportURI:       dmarcResult.Policy.ForensicURI,
	}

	// Set failure reasons
	authFailures := make([]string, 0)
	for _, reason := range dmarcResult.Reason {
		switch reason {
		case "SPF alignment failed", "SPF check failed":
			authFailures = append(authFailures, "spf")
			report.SPFFailure = reason
		case "DKIM alignment failed", "DKIM check failed":
			authFailures = append(authFailures, "dkim")
			report.DKIMFailure = reason
		default:
			report.DMARCFailure = reason
		}
	}
	report.AuthFailure = authFailures

	return report
}

// ShouldGenerateReport determines if a DMARC report should be generated
func (v *DMARCVerifier) ShouldGenerateReport(dmarcResult *types.DMARCResult) bool {
	if dmarcResult == nil || dmarcResult.Policy == nil {
		return false
	}

	// Generate aggregate reports if RUA is specified
	if len(dmarcResult.Policy.ReportURI) > 0 {
		return true
	}

	// Generate forensic reports for failures if RUF is specified
	if !dmarcResult.Valid && len(dmarcResult.Policy.ForensicURI) > 0 {
		return true
	}

	return false
}

// queryPolicyWithSubdomain queries DMARC policy with subdomain policy support
func (v *DMARCVerifier) queryPolicyWithSubdomain(ctx context.Context, fromDomain, orgDomain string) (*types.DMARCPolicy, error) {
	isSubdomain := !strings.EqualFold(fromDomain, orgDomain)

	// First, try to get policy from the organizational domain
	policy, err := v.queryPolicy(ctx, orgDomain)
	if err != nil {
		return nil, err
	}

	if policy == nil {
		return nil, nil
	}

	// If this is a subdomain and has a specific subdomain policy, apply it
	if isSubdomain && policy.SubdomainPolicy != "" {
		// Create a copy of the policy with subdomain-specific settings
		subdomainPolicy := *policy
		subdomainPolicy.Policy = policy.SubdomainPolicy
		subdomainPolicy.Domain = fromDomain // Mark it as applying to the subdomain

		if v.logger != nil {
			v.logger.Debug("Applying subdomain DMARC policy",
				zap.String("from_domain", fromDomain),
				zap.String("org_domain", orgDomain),
				zap.String("main_policy", policy.Policy),
				zap.String("subdomain_policy", policy.SubdomainPolicy))
		}

		return &subdomainPolicy, nil
	}

	// For non-subdomains or when no specific subdomain policy exists,
	// use the main policy
	if v.logger != nil && isSubdomain {
		v.logger.Debug("Using main DMARC policy for subdomain",
			zap.String("from_domain", fromDomain),
			zap.String("org_domain", orgDomain),
			zap.String("policy", policy.Policy))
	}

	return policy, nil
}

// applyPolicyWithSubdomain determines the final disposition with subdomain support
func (v *DMARCVerifier) applyPolicyWithSubdomain(policy *types.DMARCPolicy, alignment *types.DMARCAlignmentResult, fromDomain, orgDomain string) (string, []string) {
	reasons := make([]string, 0)
	isSubdomain := !strings.EqualFold(fromDomain, orgDomain)

	// Check if either SPF or DKIM is aligned
	if alignment.SPFAligned || alignment.DKIMAligned {
		return "none", reasons // DMARC passes
	}

	// DMARC failed - determine which policy to apply
	var effectivePolicy string
	if isSubdomain && policy.SubdomainPolicy != "" {
		effectivePolicy = policy.SubdomainPolicy
		reasons = append(reasons, "subdomain policy applied")
	} else {
		effectivePolicy = policy.Policy
	}

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

	// Apply percentage policy
	if policy.Percentage < 100 {
		reasons = append(reasons, fmt.Sprintf("policy percentage: %d%%", policy.Percentage))
	}

	if v.logger != nil && isSubdomain && policy.SubdomainPolicy != "" {
		v.logger.Debug("Applied subdomain DMARC disposition",
			zap.String("from_domain", fromDomain),
			zap.String("main_policy", policy.Policy),
			zap.String("subdomain_policy", policy.SubdomainPolicy),
			zap.String("effective_policy", effectivePolicy))
	}

	return effectivePolicy, reasons
}

// isSubdomain checks if a domain is a subdomain of another domain
func (v *DMARCVerifier) isSubdomain(domain, parentDomain string) bool {
	if strings.EqualFold(domain, parentDomain) {
		return false
	}

	// Normalize domains to lowercase
	domain = strings.ToLower(domain)
	parentDomain = strings.ToLower(parentDomain)

	// Check if domain ends with ".parentDomain"
	suffix := "." + parentDomain
	return strings.HasSuffix(domain, suffix)
}