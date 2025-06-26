package dkim

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

// DMARCQueryService implements the DMARCQueryInterface for future DMARC module integration
type DMARCQueryService struct {
	dnsDKIMFunc func(context.Context, string) ([]string, uint32, error) // Reuse DKIM DNS function
	cache       map[string]*types.DMARCPolicy                          // Simple in-memory cache
	logger      *zap.Logger
}

// NewDMARCQueryService creates a new DMARC query service
func NewDMARCQueryService(dnsFunc func(context.Context, string) ([]string, uint32, error), logger *zap.Logger) *DMARCQueryService {
	return &DMARCQueryService{
		dnsDKIMFunc: dnsFunc,
		cache:       make(map[string]*types.DMARCPolicy),
		logger:      logger,
	}
}

// QueryPolicy retrieves DMARC policy for a domain
func (d *DMARCQueryService) QueryPolicy(ctx context.Context, domain string) (*types.DMARCPolicy, error) {
	if domain == "" {
		return nil, fmt.Errorf("empty domain provided")
	}

	// Normalize domain
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Construct DMARC DNS query
	dmarcDomain := fmt.Sprintf("_dmarc.%s", domain)

	if d.logger != nil {
		d.logger.Debug("querying DMARC policy",
			zap.String("domain", domain),
			zap.String("dmarc_domain", dmarcDomain))
	}

	// Perform DNS TXT lookup
	records, ttl, err := d.dnsDKIMFunc(ctx, dmarcDomain)
	if err != nil {
		if d.logger != nil {
			d.logger.Debug("DMARC DNS lookup failed",
				zap.String("domain", domain),
				zap.Error(err))
		}
		return nil, fmt.Errorf("DMARC DNS lookup failed for %s: %w", domain, err)
	}

	// Find DMARC record
	var dmarcRecord string
	for _, record := range records {
		if strings.HasPrefix(record, "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		if d.logger != nil {
			d.logger.Debug("no DMARC record found",
				zap.String("domain", domain),
				zap.Strings("records", records))
		}
		return nil, fmt.Errorf("no DMARC record found for %s", domain)
	}

	// Parse DMARC record
	policy, err := d.parseDMARCRecord(dmarcRecord, domain, ttl)
	if err != nil {
		if d.logger != nil {
			d.logger.Debug("failed to parse DMARC record",
				zap.String("domain", domain),
				zap.String("record", dmarcRecord),
				zap.Error(err))
		}
		return nil, fmt.Errorf("failed to parse DMARC record for %s: %w", domain, err)
	}

	if d.logger != nil {
		d.logger.Debug("DMARC policy retrieved",
			zap.String("domain", domain),
			zap.String("policy", policy.Policy),
			zap.String("spf_alignment", string(policy.SPFAlignment)),
			zap.String("dkim_alignment", string(policy.DKIMAlignment)))
	}

	return policy, nil
}

// QueryWithCache retrieves DMARC policy with caching
func (d *DMARCQueryService) QueryWithCache(ctx context.Context, domain string) (*types.DMARCPolicy, error) {
	// Check cache first
	if policy, exists := d.cache[domain]; exists {
		// Simple TTL check (in production, implement proper expiration)
		if d.logger != nil {
			d.logger.Debug("DMARC policy cache hit",
				zap.String("domain", domain))
		}
		return policy, nil
	}

	// Cache miss, perform lookup
	policy, err := d.QueryPolicy(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Cache the result
	d.cache[domain] = policy

	if d.logger != nil {
		d.logger.Debug("DMARC policy cached",
			zap.String("domain", domain),
			zap.Uint32("ttl", policy.TTL))
	}

	return policy, nil
}

// GetOrganizationalDomain extracts organizational domain
func (d *DMARCQueryService) GetOrganizationalDomain(domain string) *types.OrganizationalDomain {
	return GetOrganizationalDomainDetailed(domain)
}

// CheckAlignment performs DMARC alignment checking
func (d *DMARCQueryService) CheckAlignment(fromDomain string, spfResult *types.SPFResult, dkimResult *types.DKIMResult, policy *types.DMARCPolicy) *types.DMARCAlignmentResult {
	if fromDomain == "" || policy == nil {
		return &types.DMARCAlignmentResult{
			FromDomain: fromDomain,
		}
	}

	result := &types.DMARCAlignmentResult{
		FromDomain: fromDomain,
		SPFMode:    policy.SPFAlignment,
		DKIMMode:   policy.DKIMAlignment,
	}

	// Check SPF alignment
	if spfResult != nil && spfResult.Result == "pass" {
		result.SPFDomain = spfResult.Domain
		result.SPFAligned = d.checkDomainAlignment(fromDomain, spfResult.Domain, policy.SPFAlignment)
	}

	// Check DKIM alignment
	if dkimResult != nil && dkimResult.Valid {
		result.DKIMDomain = dkimResult.Domain
		result.DKIMAligned = CheckDMARCAlignment(fromDomain, dkimResult, policy.DKIMAlignment)
	}

	if d.logger != nil {
		d.logger.Debug("DMARC alignment check completed",
			zap.String("from_domain", fromDomain),
			zap.Bool("spf_aligned", result.SPFAligned),
			zap.Bool("dkim_aligned", result.DKIMAligned),
			zap.String("spf_domain", result.SPFDomain),
			zap.String("dkim_domain", result.DKIMDomain))
	}

	return result
}

// checkDomainAlignment checks domain alignment for SPF or DKIM
func (d *DMARCQueryService) checkDomainAlignment(fromDomain, authDomain string, mode types.DMARCAlignmentMode) bool {
	if authDomain == "" {
		return false
	}

	switch mode {
	case types.AlignmentStrict:
		return strings.EqualFold(fromDomain, authDomain)
	case types.AlignmentRelaxed:
		fromOrgDomain := d.GetOrganizationalDomain(fromDomain)
		authOrgDomain := d.GetOrganizationalDomain(authDomain)
		
		if fromOrgDomain == nil || authOrgDomain == nil {
			return false
		}
		
		return strings.EqualFold(fromOrgDomain.OrgDomain, authOrgDomain.OrgDomain)
	default:
		// Default to relaxed
		return d.checkDomainAlignment(fromDomain, authDomain, types.AlignmentRelaxed)
	}
}

// parseDMARCRecord parses a DMARC TXT record into a DMARCPolicy structure
func (d *DMARCQueryService) parseDMARCRecord(record, domain string, ttl uint32) (*types.DMARCPolicy, error) {
	policy := &types.DMARCPolicy{
		Domain:          domain,
		TTL:             ttl,
		SPFAlignment:    types.AlignmentRelaxed,  // Default values
		DKIMAlignment:   types.AlignmentRelaxed,
		Percentage:      100,
		ReportURI:       make([]string, 0),
		ForensicURI:     make([]string, 0),
	}

	// Split record into tag-value pairs
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split tag=value
		tagValue := strings.SplitN(part, "=", 2)
		if len(tagValue) != 2 {
			continue
		}

		tag := strings.TrimSpace(tagValue[0])
		value := strings.TrimSpace(tagValue[1])

		switch tag {
		case "v":
			if value != "DMARC1" {
				return nil, fmt.Errorf("unsupported DMARC version: %s", value)
			}
		case "p":
			policy.Policy = value
		case "sp":
			policy.SubdomainPolicy = value
		case "aspf":
			if value == "s" {
				policy.SPFAlignment = types.AlignmentStrict
			}
		case "adkim":
			if value == "s" {
				policy.DKIMAlignment = types.AlignmentStrict
			}
		case "pct":
			if pct, err := strconv.Atoi(value); err == nil && pct >= 0 && pct <= 100 {
				policy.Percentage = pct
			}
		case "rua":
			// Aggregate report URIs
			uris := strings.Split(value, ",")
			for _, uri := range uris {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					policy.ReportURI = append(policy.ReportURI, uri)
				}
			}
		case "ruf":
			// Forensic report URIs
			uris := strings.Split(value, ",")
			for _, uri := range uris {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					policy.ForensicURI = append(policy.ForensicURI, uri)
				}
			}
		}
	}

	// Validate required fields
	if policy.Policy == "" {
		return nil, fmt.Errorf("missing required 'p' tag in DMARC record")
	}

	if policy.Policy != "none" && policy.Policy != "quarantine" && policy.Policy != "reject" {
		return nil, fmt.Errorf("invalid DMARC policy: %s", policy.Policy)
	}

	return policy, nil
}

// EvaluateDMARC performs a complete DMARC evaluation (placeholder for future implementation)
func EvaluateDMARC(fromDomain string, spfResult *types.SPFResult, dkimResult *types.DKIMResult, dmarcService *DMARCQueryService) *types.DMARCResult {
	result := &types.DMARCResult{
		Valid:       false,
		Disposition: "none",
		Reason:      make([]string, 0),
		Score:       0.0,
	}

	if fromDomain == "" {
		result.Error = "missing From domain"
		return result
	}

	// Get DMARC policy
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	policy, err := dmarcService.QueryWithCache(ctx, fromDomain)
	if err != nil {
		result.Error = fmt.Sprintf("DMARC policy lookup failed: %v", err)
		result.Score = 0.5 // Slight penalty for missing DMARC
		return result
	}

	result.Policy = policy

	// Check alignment
	alignment := dmarcService.CheckAlignment(fromDomain, spfResult, dkimResult, policy)
	result.Alignment = alignment

	// Determine DMARC result
	// DMARC passes if either SPF or DKIM is aligned
	if alignment.SPFAligned || alignment.DKIMAligned {
		result.Valid = true
		result.Disposition = "none"
		result.Score = -1.0 // Good score for DMARC pass
	} else {
		result.Valid = false
		result.Reason = append(result.Reason, "no_aligned_identifiers")
		
		// Apply policy
		switch policy.Policy {
		case "none":
			result.Disposition = "none"
			result.Score = 1.0 // Mild penalty
		case "quarantine":
			result.Disposition = "quarantine"
			result.Score = 3.0 // Moderate penalty
		case "reject":
			result.Disposition = "reject"
			result.Score = 5.0 // High penalty
		}
	}

	// Apply percentage policy
	if policy.Percentage < 100 {
		// In a real implementation, this would use random sampling
		// For now, we'll just note it in the result
		result.Reason = append(result.Reason, fmt.Sprintf("percentage_policy_%d", policy.Percentage))
	}

	return result
}

// ExtractFromDomain extracts the domain from a From header address
func ExtractFromDomain(fromHeader string) string {
	if fromHeader == "" {
		return ""
	}

	// Simple email address parsing
	// In production, use a proper email parser
	emailRegex := regexp.MustCompile(`<([^>]+)>|([^\s<>]+@[^\s<>]+)`)
	matches := emailRegex.FindStringSubmatch(fromHeader)
	
	var email string
	if len(matches) > 1 && matches[1] != "" {
		email = matches[1] // Email in angle brackets
	} else if len(matches) > 2 && matches[2] != "" {
		email = matches[2] // Plain email
	} else {
		// Try to extract email-like string
		parts := strings.Fields(fromHeader)
		for _, part := range parts {
			if strings.Contains(part, "@") {
				email = strings.Trim(part, "<>")
				break
			}
		}
	}

	if email == "" {
		return ""
	}

	// Extract domain part
	atIndex := strings.LastIndex(email, "@")
	if atIndex == -1 || atIndex == len(email)-1 {
		return ""
	}

	domain := email[atIndex+1:]
	return strings.ToLower(strings.TrimSpace(domain))
}