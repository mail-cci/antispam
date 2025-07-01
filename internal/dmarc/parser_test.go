package dmarc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/mail-cci/antispam/internal/types"
)

func TestDMARCParserParseRecord(t *testing.T) {
	logger := zap.NewNop()
	parser := NewParser(logger)

	tests := []struct {
		name          string
		record        string
		expectError   bool
		expectedError string
		validate      func(t *testing.T, policy *types.DMARCPolicy)
	}{
		{
			name:   "valid basic record",
			record: "v=DMARC1; p=quarantine",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "DMARC1", policy.Version)
				assert.Equal(t, "quarantine", policy.Policy)
				assert.Equal(t, "quarantine", policy.SubdomainPolicy) // Should default to main policy
				assert.Equal(t, types.AlignmentRelaxed, policy.SPFAlignment)
				assert.Equal(t, types.AlignmentRelaxed, policy.DKIMAlignment)
				assert.Equal(t, 100, policy.Percentage)
				assert.Equal(t, []string{"0"}, policy.FailureOptions)
				assert.Equal(t, uint32(86400), policy.ReportInterval)
			},
		},
		{
			name:   "comprehensive record",
			record: "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=75; rua=mailto:dmarc@example.com,mailto:backup@example.com; ruf=mailto:forensic@example.com; fo=1:d:s; ri=604800",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "DMARC1", policy.Version)
				assert.Equal(t, "reject", policy.Policy)
				assert.Equal(t, "quarantine", policy.SubdomainPolicy)
				assert.Equal(t, types.AlignmentStrict, policy.SPFAlignment)
				assert.Equal(t, types.AlignmentStrict, policy.DKIMAlignment)
				assert.Equal(t, 75, policy.Percentage)
				assert.Equal(t, []string{"mailto:dmarc@example.com", "mailto:backup@example.com"}, policy.ReportURI)
				assert.Equal(t, []string{"mailto:forensic@example.com"}, policy.ForensicURI)
				assert.Equal(t, []string{"1", "d", "s"}, policy.FailureOptions)
				assert.Equal(t, uint32(604800), policy.ReportInterval)
			},
		},
		{
			name:   "relaxed alignment modes",
			record: "v=DMARC1; p=none; adkim=r; aspf=r",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, types.AlignmentRelaxed, policy.SPFAlignment)
				assert.Equal(t, types.AlignmentRelaxed, policy.DKIMAlignment)
			},
		},
		{
			name:   "with unknown tags",
			record: "v=DMARC1; p=none; customtag=value; anothertag=test",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Contains(t, policy.UnknownTags, "customtag")
				assert.Contains(t, policy.UnknownTags, "anothertag")
				assert.Equal(t, "value", policy.UnknownTags["customtag"])
				assert.Equal(t, "test", policy.UnknownTags["anothertag"])
			},
		},
		{
			name:   "with extra whitespace",
			record: "  v = DMARC1 ;  p = quarantine  ; pct =  50 ; ",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "DMARC1", policy.Version)
				assert.Equal(t, "quarantine", policy.Policy)
				assert.Equal(t, 50, policy.Percentage)
			},
		},
		{
			name:        "empty record",
			record:      "",
			expectError: true,
		},
		{
			name:        "missing version tag",
			record:      "p=quarantine; adkim=s",
			expectError: true,
		},
		{
			name:        "invalid version",
			record:      "v=DMARC2; p=quarantine",
			expectError: true,
		},
		{
			name:        "missing policy tag",
			record:      "v=DMARC1; adkim=s",
			expectError: true,
		},
		{
			name:        "invalid policy value",
			record:      "v=DMARC1; p=invalid",
			expectError: true,
		},
		{
			name:   "invalid subdomain policy with parse error",
			record: "v=DMARC1; p=none; sp=invalid",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, "none", policy.SubdomainPolicy) // Should default to main policy
				assert.NotEmpty(t, policy.ParseErrors)
				assert.Contains(t, policy.ParseErrors[0], "invalid subdomain policy value")
			},
		},
		{
			name:   "invalid percentage with parse error",
			record: "v=DMARC1; p=none; pct=150",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, 100, policy.Percentage) // Should keep default
				assert.NotEmpty(t, policy.ParseErrors)
				assert.Contains(t, policy.ParseErrors[0], "percentage out of range")
			},
		},
		{
			name:   "invalid alignment mode",
			record: "v=DMARC1; p=none; adkim=invalid",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, types.AlignmentRelaxed, policy.DKIMAlignment) // Should keep default
				assert.NotEmpty(t, policy.ParseErrors)
			},
		},
		{
			name:   "duplicate tags",
			record: "v=DMARC1; p=none; p=quarantine; adkim=s; adkim=r",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy) // Should use first occurrence
				assert.Equal(t, types.AlignmentStrict, policy.DKIMAlignment) // Should use first occurrence
				assert.Contains(t, policy.ParseErrors[0], "duplicate tag")
			},
		},
		{
			name:        "malformed tag-value pairs",
			record:      "v=DMARC1; invalid-pair; p=none",
			expectError: true,
		},
		{
			name:        "invalid tag name",
			record:      "v=DMARC1; p@invalid=none",
			expectError: true,
		},
		{
			name:        "record too long",
			record:      "v=DMARC1; p=none; " + generateLongString(4100),
			expectError: true,
		},
		{
			name:   "invalid report URIs",
			record: "v=DMARC1; p=none; rua=invalid-uri,mailto:valid@example.com",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, []string{"mailto:valid@example.com"}, policy.ReportURI)
			},
		},
		{
			name:   "invalid failure options",
			record: "v=DMARC1; p=none; fo=invalid:1:d",
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, []string{"0"}, policy.FailureOptions) // Should keep default
				assert.NotEmpty(t, policy.ParseErrors)
			},
		},
		{
			name:   "invalid report interval",
			record: "v=DMARC1; p=none; ri=100", // Too small
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, uint32(86400), policy.ReportInterval) // Should keep default
				assert.NotEmpty(t, policy.ParseErrors)
			},
		},
		{
			name:   "forensic reporting without URIs",
			record: "v=DMARC1; p=none; fo=1", // Enables forensic but no ruf
			validate: func(t *testing.T, policy *types.DMARCPolicy) {
				assert.Equal(t, "none", policy.Policy)
				assert.Equal(t, []string{"1"}, policy.FailureOptions)
				assert.NotEmpty(t, policy.ParseErrors)
				assert.Contains(t, policy.ParseErrors[0], "forensic reporting enabled but no forensic URIs")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := parser.ParseDMARCRecord(tt.record)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, policy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy)
				assert.Equal(t, tt.record, policy.RawRecord)
				
				if tt.validate != nil {
					tt.validate(t, policy)
				}
			}
		})
	}
}

func TestDMARCParserValidateReportURI(t *testing.T) {
	logger := zap.NewNop()
	parser := NewParser(logger)

	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{
			name: "valid mailto URI",
			uri:  "mailto:dmarc@example.com",
		},
		{
			name: "valid https URI",
			uri:  "https://example.com/dmarc",
		},
		{
			name: "valid http URI",
			uri:  "http://example.com/dmarc",
		},
		{
			name:        "invalid scheme",
			uri:         "ftp://example.com/dmarc",
			expectError: true,
		},
		{
			name:        "invalid mailto",
			uri:         "mailto:",
			expectError: true,
		},
		{
			name:        "malformed URI",
			uri:         "not-a-uri",
			expectError: true,
		},
		{
			name:        "empty URI",
			uri:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parser.validateReportURI(tt.uri)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDMARCParserTagValuePairs(t *testing.T) {
	logger := zap.NewNop()
	parser := NewParser(logger)

	tests := []struct {
		name        string
		record      string
		expectError bool
		expected    []tagValuePair
	}{
		{
			name:   "basic pairs",
			record: "v=DMARC1; p=none",
			expected: []tagValuePair{
				{Tag: "v", Value: "DMARC1"},
				{Tag: "p", Value: "none"},
			},
		},
		{
			name:   "with whitespace",
			record: " v = DMARC1 ; p = none ; ",
			expected: []tagValuePair{
				{Tag: "v", Value: "DMARC1"},
				{Tag: "p", Value: "none"},
			},
		},
		{
			name:   "empty segments ignored",
			record: "v=DMARC1;; p=none; ;",
			expected: []tagValuePair{
				{Tag: "v", Value: "DMARC1"},
				{Tag: "p", Value: "none"},
			},
		},
		{
			name:        "malformed pair",
			record:      "v=DMARC1; invalid-pair",
			expectError: true,
		},
		{
			name:        "invalid tag name",
			record:      "v=DMARC1; p@invalid=none",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pairs, err := parser.parseTagValuePairs(tt.record)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, pairs)
			}
		})
	}
}

func TestIsValidTagName(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		expected bool
	}{
		{"valid lowercase", "v", true},
		{"valid uppercase", "P", true},
		{"valid mixed case", "AdKiM", true},
		{"valid with numbers", "tag123", true},
		{"valid with underscore", "custom_tag", true},
		{"empty tag", "", false},
		{"with hyphen", "custom-tag", false},
		{"with space", "custom tag", false},
		{"with special chars", "tag@domain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidTagName(tt.tag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDMARCParserEdgeCases(t *testing.T) {
	logger := zap.NewNop()
	parser := NewParser(logger)

	t.Run("very long but valid record", func(t *testing.T) {
		// Create a record with many valid URIs
		var uris []string
		for i := 0; i < 50; i++ {
			uris = append(uris, "mailto:dmarc"+fmt.Sprintf("%d", i)+"@example.com")
		}
		record := "v=DMARC1; p=none; rua=" + strings.Join(uris, ",")
		
		policy, err := parser.ParseDMARCRecord(record)
		require.NoError(t, err)
		assert.Equal(t, "none", policy.Policy)
		assert.Len(t, policy.ReportURI, 50)
	})

	t.Run("record with special characters in values", func(t *testing.T) {
		record := "v=DMARC1; p=none; rua=mailto:dmarc+test@example.com"
		policy, err := parser.ParseDMARCRecord(record)
		require.NoError(t, err)
		assert.Equal(t, []string{"mailto:dmarc+test@example.com"}, policy.ReportURI)
	})

	t.Run("case insensitive parsing", func(t *testing.T) {
		record := "V=DMARC1; P=QUARANTINE; ADKIM=S; ASPF=R"
		policy, err := parser.ParseDMARCRecord(record)
		require.NoError(t, err)
		assert.Equal(t, "DMARC1", policy.Version)
		assert.Equal(t, "quarantine", policy.Policy)
		assert.Equal(t, types.AlignmentStrict, policy.DKIMAlignment)
		assert.Equal(t, types.AlignmentRelaxed, policy.SPFAlignment)
	})
}

func TestDMARCParserPerformance(t *testing.T) {
	logger := zap.NewNop()
	parser := NewParser(logger)
	
	// Complex record for performance testing
	record := "v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@example.com,mailto:backup@example.com; ruf=mailto:forensic@example.com; fo=1:d:s; ri=86400"

	t.Run("parse performance", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			_, err := parser.ParseDMARCRecord(record)
			require.NoError(t, err)
		}
	})
}

// Helper function to generate long strings for testing
func generateLongString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = 'a'
	}
	return string(result)
}

// Benchmark tests
func BenchmarkDMARCParserParseRecord(b *testing.B) {
	logger := zap.NewNop()
	parser := NewParser(logger)
	record := "v=DMARC1; p=quarantine; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@example.com,mailto:backup@example.com; ruf=mailto:forensic@example.com; fo=1:d:s; ri=86400"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parser.ParseDMARCRecord(record)
	}
}

func BenchmarkDMARCParserValidateURI(b *testing.B) {
	logger := zap.NewNop()
	parser := NewParser(logger)
	uri := "mailto:dmarc@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parser.validateReportURI(uri)
	}
}