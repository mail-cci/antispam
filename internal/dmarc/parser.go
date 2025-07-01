package dmarc

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

// DMARCParser handles parsing of DMARC DNS TXT records according to RFC 7489
type DMARCParser struct {
	logger *zap.Logger
}

// NewParser creates a new DMARC parser
func NewParser(logger *zap.Logger) *DMARCParser {
	return &DMARCParser{
		logger: logger,
	}
}

// parseError represents a parsing error with context
type parseError struct {
	Tag     string
	Value   string
	Message string
}

func (pe parseError) String() string {
	return fmt.Sprintf("tag '%s' with value '%s': %s", pe.Tag, pe.Value, pe.Message)
}

// validPolicyValues contains valid DMARC policy values
var validPolicyValues = map[string]bool{
	"none":       true,
	"quarantine": true,
	"reject":     true,
}

// validAlignmentValues contains valid alignment mode values
var validAlignmentValues = map[string]bool{
	"r": true, // relaxed
	"s": true, // strict
}

// validFailureOptions contains valid forensic report options
var validFailureOptions = map[string]bool{
	"0": true, // Generate reports if all underlying authentication mechanisms fail
	"1": true, // Generate reports if any underlying authentication mechanism fails
	"d": true, // Generate reports if DKIM signature verification fails
	"s": true, // Generate reports if SPF verification fails
}

// uriRegex for basic URI validation
var uriRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)

// ParseDMARCRecord parses a DMARC DNS TXT record with comprehensive validation
func (p *DMARCParser) ParseDMARCRecord(record string) (*types.DMARCPolicy, error) {
	if record == "" {
		return nil, fmt.Errorf("empty DMARC record")
	}

	// Initialize policy with defaults
	policy := &types.DMARCPolicy{
		Policy:          "",    // Required field, no default
		SubdomainPolicy: "",    // Optional, defaults to Policy if not specified
		SPFAlignment:    types.AlignmentRelaxed,
		DKIMAlignment:   types.AlignmentRelaxed,
		Percentage:      100,
		ReportURI:       make([]string, 0),
		ForensicURI:     make([]string, 0),
		FailureOptions:  []string{"0"}, // Default: report if all mechanisms fail
		ReportInterval:  86400,          // Default: 24 hours
		Version:         "",             // Will be validated
		RawRecord:       record,
		ParseErrors:     make([]string, 0),
		UnknownTags:     make(map[string]string),
	}

	// Step 1: Basic format validation
	if err := p.validateRecordFormat(record); err != nil {
		return nil, fmt.Errorf("invalid record format: %w", err)
	}

	// Step 2: Parse tag-value pairs
	pairs, err := p.parseTagValuePairs(record)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tag-value pairs: %w", err)
	}

	// Step 3: Validate version first (must be present and valid)
	versionFound := false
	for _, pair := range pairs {
		if strings.ToLower(pair.Tag) == "v" {
			versionFound = true
			if err := p.parseVersionTag(pair.Value, policy); err != nil {
				return nil, fmt.Errorf("invalid version: %w", err)
			}
			break
		}
	}

	if !versionFound {
		return nil, fmt.Errorf("missing required 'v' tag")
	}

	// Step 4: Parse all other tags
	policyFound := false
	seenTags := make(map[string]bool)

	for _, pair := range pairs {
		tag := strings.ToLower(pair.Tag)

		// Check for duplicate tags (use first occurrence)
		if seenTags[tag] {
			policy.ParseErrors = append(policy.ParseErrors, 
				fmt.Sprintf("duplicate tag '%s' found, using first occurrence", tag))
			continue
		}
		seenTags[tag] = true

		switch tag {
		case "v":
			// Already processed
			continue
		case "p":
			policyFound = true
			if err := p.parsePolicyTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "sp":
			if err := p.parseSubdomainPolicyTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "adkim":
			if err := p.parseDKIMAlignmentTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "aspf":
			if err := p.parseSPFAlignmentTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "pct":
			if err := p.parsePercentageTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "rua":
			if err := p.parseReportURITag(pair.Value, policy, true); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "ruf":
			if err := p.parseReportURITag(pair.Value, policy, false); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "fo":
			if err := p.parseFailureOptionsTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		case "ri":
			if err := p.parseReportIntervalTag(pair.Value, policy); err != nil {
				policy.ParseErrors = append(policy.ParseErrors, err.Error())
			}
		default:
			// Unknown tag - store for reference
			policy.UnknownTags[pair.Tag] = pair.Value
			if p.logger != nil {
				p.logger.Debug("Unknown DMARC tag found",
					zap.String("tag", pair.Tag),
					zap.String("value", pair.Value))
			}
		}
	}

	// Step 5: Validate required fields
	if !policyFound {
		return nil, fmt.Errorf("missing required 'p' tag")
	}

	// Step 6: Apply defaults for optional fields
	p.applyDefaults(policy)

	// Step 7: Final validation
	if err := p.validateFinalPolicy(policy); err != nil {
		return nil, fmt.Errorf("policy validation failed: %w", err)
	}

	if p.logger != nil {
		p.logger.Debug("DMARC record parsed successfully",
			zap.String("policy", policy.Policy),
			zap.Int("parse_errors", len(policy.ParseErrors)),
			zap.Int("unknown_tags", len(policy.UnknownTags)))
	}

	return policy, nil
}

// tagValuePair represents a parsed tag-value pair
type tagValuePair struct {
	Tag   string
	Value string
}

// validateRecordFormat performs basic format validation
func (p *DMARCParser) validateRecordFormat(record string) error {
	// Check for basic structure
	if !strings.Contains(record, "=") {
		return fmt.Errorf("no tag-value pairs found")
	}

	// Check for reasonable length (RFC doesn't specify max, but DNS TXT has limits)
	if len(record) > 4096 {
		return fmt.Errorf("record too long (%d bytes, max 4096)", len(record))
	}

	return nil
}

// parseTagValuePairs extracts and cleans tag-value pairs
func (p *DMARCParser) parseTagValuePairs(record string) ([]tagValuePair, error) {
	var pairs []tagValuePair

	// Split by semicolon
	segments := strings.Split(record, ";")

	for i, segment := range segments {
		// Clean whitespace
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}

		// Split tag=value
		parts := strings.SplitN(segment, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed tag-value pair at position %d: '%s'", i, segment)
		}

		tag := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Validate tag format (alphanumeric + underscore)
		if !isValidTagName(tag) {
			return nil, fmt.Errorf("invalid tag name at position %d: '%s'", i, tag)
		}

		pairs = append(pairs, tagValuePair{
			Tag:   tag,
			Value: value,
		})
	}

	if len(pairs) == 0 {
		return nil, fmt.Errorf("no valid tag-value pairs found")
	}

	return pairs, nil
}

// isValidTagName checks if a tag name is valid
func isValidTagName(tag string) bool {
	if tag == "" {
		return false
	}
	for _, char := range tag {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	return true
}

// parseVersionTag validates and parses the version tag
func (p *DMARCParser) parseVersionTag(value string, policy *types.DMARCPolicy) error {
	value = strings.TrimSpace(value)
	if value != "DMARC1" {
		return fmt.Errorf("unsupported DMARC version: '%s', expected 'DMARC1'", value)
	}
	policy.Version = value
	return nil
}

// parsePolicyTag validates and parses the policy tag
func (p *DMARCParser) parsePolicyTag(value string, policy *types.DMARCPolicy) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if !validPolicyValues[value] {
		return fmt.Errorf("invalid policy value: '%s', must be one of: none, quarantine, reject", value)
	}
	policy.Policy = value
	return nil
}

// parseSubdomainPolicyTag validates and parses the subdomain policy tag
func (p *DMARCParser) parseSubdomainPolicyTag(value string, policy *types.DMARCPolicy) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if !validPolicyValues[value] {
		return fmt.Errorf("invalid subdomain policy value: '%s', must be one of: none, quarantine, reject", value)
	}
	policy.SubdomainPolicy = value
	return nil
}

// parseDKIMAlignmentTag validates and parses the DKIM alignment tag
func (p *DMARCParser) parseDKIMAlignmentTag(value string, policy *types.DMARCPolicy) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if !validAlignmentValues[value] {
		return fmt.Errorf("invalid DKIM alignment value: '%s', must be 'r' (relaxed) or 's' (strict)", value)
	}
	
	if value == "s" {
		policy.DKIMAlignment = types.AlignmentStrict
	} else {
		policy.DKIMAlignment = types.AlignmentRelaxed
	}
	return nil
}

// parseSPFAlignmentTag validates and parses the SPF alignment tag
func (p *DMARCParser) parseSPFAlignmentTag(value string, policy *types.DMARCPolicy) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if !validAlignmentValues[value] {
		return fmt.Errorf("invalid SPF alignment value: '%s', must be 'r' (relaxed) or 's' (strict)", value)
	}
	
	if value == "s" {
		policy.SPFAlignment = types.AlignmentStrict
	} else {
		policy.SPFAlignment = types.AlignmentRelaxed
	}
	return nil
}

// parsePercentageTag validates and parses the percentage tag
func (p *DMARCParser) parsePercentageTag(value string, policy *types.DMARCPolicy) error {
	value = strings.TrimSpace(value)
	pct, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("invalid percentage value: '%s', must be a number", value)
	}
	
	if pct < 0 || pct > 100 {
		return fmt.Errorf("percentage out of range: %d, must be between 0 and 100", pct)
	}
	
	policy.Percentage = pct
	return nil
}

// parseReportURITag validates and parses report URI tags (rua/ruf)
func (p *DMARCParser) parseReportURITag(value string, policy *types.DMARCPolicy, isAggregate bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("empty report URI value")
	}

	// Split multiple URIs by comma
	uris := strings.Split(value, ",")
	validURIs := make([]string, 0, len(uris))

	for i, uri := range uris {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}

		// Basic URI format validation
		if err := p.validateReportURI(uri); err != nil {
			if p.logger != nil {
				p.logger.Debug("Invalid report URI",
					zap.String("uri", uri),
					zap.Int("position", i),
					zap.Error(err))
			}
			// Don't fail the entire record for one bad URI
			continue
		}

		validURIs = append(validURIs, uri)
	}

	if len(validURIs) == 0 {
		return fmt.Errorf("no valid URIs found in report URI list")
	}

	if isAggregate {
		policy.ReportURI = validURIs
	} else {
		policy.ForensicURI = validURIs
	}

	return nil
}

// validateReportURI performs basic URI validation
func (p *DMARCParser) validateReportURI(uri string) error {
	// Check basic URI format
	if !uriRegex.MatchString(uri) {
		return fmt.Errorf("invalid URI format: '%s'", uri)
	}

	// Parse URI for more detailed validation
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("failed to parse URI: %w", err)
	}

	// Check for supported schemes
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "mailto" && scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URI scheme: '%s'", scheme)
	}

	// Additional validation for mailto URIs
	if scheme == "mailto" && parsed.Opaque == "" {
		return fmt.Errorf("invalid mailto URI: missing email address")
	}

	return nil
}

// parseFailureOptionsTag validates and parses the failure options tag
func (p *DMARCParser) parseFailureOptionsTag(value string, policy *types.DMARCPolicy) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("empty failure options value")
	}

	// Split multiple options by colon
	options := strings.Split(value, ":")
	validOptions := make([]string, 0, len(options))

	for _, option := range options {
		option = strings.TrimSpace(option)
		if option == "" {
			continue
		}

		option = strings.ToLower(option)
		if !validFailureOptions[option] {
			return fmt.Errorf("invalid failure option: '%s', must be one of: 0, 1, d, s", option)
		}

		validOptions = append(validOptions, option)
	}

	if len(validOptions) == 0 {
		return fmt.Errorf("no valid failure options found")
	}

	policy.FailureOptions = validOptions
	return nil
}

// parseReportIntervalTag validates and parses the report interval tag
func (p *DMARCParser) parseReportIntervalTag(value string, policy *types.DMARCPolicy) error {
	value = strings.TrimSpace(value)
	interval, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid report interval value: '%s', must be a number", value)
	}

	// Reasonable bounds check (1 hour to 1 year)
	if interval < 3600 || interval > 31536000 {
		return fmt.Errorf("report interval out of range: %d, must be between 3600 and 31536000 seconds", interval)
	}

	policy.ReportInterval = uint32(interval)
	return nil
}

// applyDefaults sets default values for optional fields
func (p *DMARCParser) applyDefaults(policy *types.DMARCPolicy) {
	// If no subdomain policy specified, use main policy
	if policy.SubdomainPolicy == "" {
		policy.SubdomainPolicy = policy.Policy
	}

	// Ensure failure options has at least default value
	if len(policy.FailureOptions) == 0 {
		policy.FailureOptions = []string{"0"}
	}
}

// validateFinalPolicy performs final validation of the complete policy
func (p *DMARCParser) validateFinalPolicy(policy *types.DMARCPolicy) error {
	// Policy must be set
	if policy.Policy == "" {
		return fmt.Errorf("policy not set")
	}

	// Version must be set
	if policy.Version == "" {
		return fmt.Errorf("version not set")
	}

	// If forensic reporting is enabled, must have forensic URIs
	hasForensicOptions := false
	for _, option := range policy.FailureOptions {
		if option == "1" || option == "d" || option == "s" {
			hasForensicOptions = true
			break
		}
	}

	if hasForensicOptions && len(policy.ForensicURI) == 0 {
		policy.ParseErrors = append(policy.ParseErrors,
			"forensic reporting enabled but no forensic URIs (ruf) specified")
	}

	return nil
}