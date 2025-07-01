package dmarc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/mail-cci/antispam/internal/types"
)

func TestParseDMARCRecord(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	tests := []struct {
		name     string
		record   string
		expected *types.DMARCPolicy
	}{
		{
			name:   "basic policy",
			record: "v=DMARC1; p=quarantine",
			expected: &types.DMARCPolicy{
				Policy:          "quarantine",
				SubdomainPolicy: "quarantine", // Should default to main policy
				SPFAlignment:    types.AlignmentRelaxed,
				DKIMAlignment:   types.AlignmentRelaxed,
				Percentage:      100,
				ReportURI:       []string{},
				ForensicURI:     []string{},
			},
		},
		{
			name:   "strict alignment",
			record: "v=DMARC1; p=reject; adkim=s; aspf=s",
			expected: &types.DMARCPolicy{
				Policy:          "reject",
				SubdomainPolicy: "reject", // Should default to main policy
				SPFAlignment:    types.AlignmentStrict,
				DKIMAlignment:   types.AlignmentStrict,
				Percentage:      100,
				ReportURI:       []string{},
				ForensicURI:     []string{},
			},
		},
		{
			name:   "with percentage and reports",
			record: "v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com",
			expected: &types.DMARCPolicy{
				Policy:          "quarantine",
				SubdomainPolicy: "quarantine", // Should default to main policy
				SPFAlignment:    types.AlignmentRelaxed,
				DKIMAlignment:   types.AlignmentRelaxed,
				Percentage:      50,
				ReportURI:       []string{"mailto:dmarc@example.com"},
				ForensicURI:     []string{"mailto:forensic@example.com"},
			},
		},
		{
			name:   "subdomain policy",
			record: "v=DMARC1; p=none; sp=quarantine",
			expected: &types.DMARCPolicy{
				Policy:          "none",
				SubdomainPolicy: "quarantine",
				SPFAlignment:    types.AlignmentRelaxed,
				DKIMAlignment:   types.AlignmentRelaxed,
				Percentage:      100,
				ReportURI:       []string{},
				ForensicURI:     []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.parseDMARCRecord(tt.record)
			assert.Equal(t, tt.expected.Policy, result.Policy)
			assert.Equal(t, tt.expected.SubdomainPolicy, result.SubdomainPolicy)
			assert.Equal(t, tt.expected.SPFAlignment, result.SPFAlignment)
			assert.Equal(t, tt.expected.DKIMAlignment, result.DKIMAlignment)
			assert.Equal(t, tt.expected.Percentage, result.Percentage)
			assert.Equal(t, tt.expected.ReportURI, result.ReportURI)
			assert.Equal(t, tt.expected.ForensicURI, result.ForensicURI)
		})
	}
}

func TestCheckDomainAlignment(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	tests := []struct {
		name       string
		fromDomain string
		authDomain string
		mode       types.DMARCAlignmentMode
		expected   bool
	}{
		{
			name:       "exact match strict",
			fromDomain: "example.com",
			authDomain: "example.com",
			mode:       types.AlignmentStrict,
			expected:   true,
		},
		{
			name:       "exact match relaxed",
			fromDomain: "example.com",
			authDomain: "example.com",
			mode:       types.AlignmentRelaxed,
			expected:   true,
		},
		{
			name:       "subdomain strict fail",
			fromDomain: "sub.example.com",
			authDomain: "example.com",
			mode:       types.AlignmentStrict,
			expected:   false,
		},
		{
			name:       "subdomain relaxed pass",
			fromDomain: "sub.example.com",
			authDomain: "example.com",
			mode:       types.AlignmentRelaxed,
			expected:   true,
		},
		{
			name:       "different domains",
			fromDomain: "example.com",
			authDomain: "other.com",
			mode:       types.AlignmentRelaxed,
			expected:   false,
		},
		{
			name:       "case insensitive",
			fromDomain: "Example.Com",
			authDomain: "example.com",
			mode:       types.AlignmentStrict,
			expected:   true,
		},
		{
			name:       "mail subdomain relaxed",
			fromDomain: "example.com",
			authDomain: "mail.example.com",
			mode:       types.AlignmentRelaxed,
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.checkDomainAlignment(tt.fromDomain, tt.authDomain, tt.mode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckAlignment(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	policy := &types.DMARCPolicy{
		SPFAlignment:  types.AlignmentRelaxed,
		DKIMAlignment: types.AlignmentRelaxed,
	}

	tests := []struct {
		name         string
		fromDomain   string
		spfResult    *types.SPFResult
		dkimResult   *types.DKIMResult
		expectedSPF  bool
		expectedDKIM bool
	}{
		{
			name:       "both aligned",
			fromDomain: "example.com",
			spfResult: &types.SPFResult{
				Result: "pass",
				Domain: "example.com",
			},
			dkimResult: &types.DKIMResult{
				Valid: true,
				AlignmentCandidates: []types.AlignmentCandidate{
					{Domain: "example.com", Valid: true},
				},
			},
			expectedSPF:  true,
			expectedDKIM: true,
		},
		{
			name:       "SPF aligned only",
			fromDomain: "example.com",
			spfResult: &types.SPFResult{
				Result: "pass",
				Domain: "example.com",
			},
			dkimResult: &types.DKIMResult{
				Valid: true,
				AlignmentCandidates: []types.AlignmentCandidate{
					{Domain: "other.com", Valid: true},
				},
			},
			expectedSPF:  true,
			expectedDKIM: false,
		},
		{
			name:       "DKIM aligned only",
			fromDomain: "example.com",
			spfResult: &types.SPFResult{
				Result: "fail",
				Domain: "other.com",
			},
			dkimResult: &types.DKIMResult{
				Valid: true,
				AlignmentCandidates: []types.AlignmentCandidate{
					{Domain: "example.com", Valid: true},
				},
			},
			expectedSPF:  false,
			expectedDKIM: true,
		},
		{
			name:       "neither aligned",
			fromDomain: "example.com",
			spfResult: &types.SPFResult{
				Result: "fail",
				Domain: "other.com",
			},
			dkimResult: &types.DKIMResult{
				Valid:               false,
				AlignmentCandidates: []types.AlignmentCandidate{},
			},
			expectedSPF:  false,
			expectedDKIM: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.checkAlignment(tt.fromDomain, tt.spfResult, tt.dkimResult, policy)
			assert.Equal(t, tt.expectedSPF, result.SPFAligned)
			assert.Equal(t, tt.expectedDKIM, result.DKIMAligned)
			assert.Equal(t, tt.fromDomain, result.FromDomain)
		})
	}
}

func TestApplyPolicy(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	tests := []struct {
		name                string
		policy              *types.DMARCPolicy
		alignment           *types.DMARCAlignmentResult
		expectedDisposition string
		expectReasons       bool
	}{
		{
			name: "DMARC pass - SPF aligned",
			policy: &types.DMARCPolicy{
				Policy: "reject",
			},
			alignment: &types.DMARCAlignmentResult{
				SPFAligned:  true,
				DKIMAligned: false,
			},
			expectedDisposition: "none",
			expectReasons:       false,
		},
		{
			name: "DMARC pass - DKIM aligned",
			policy: &types.DMARCPolicy{
				Policy: "reject",
			},
			alignment: &types.DMARCAlignmentResult{
				SPFAligned:  false,
				DKIMAligned: true,
			},
			expectedDisposition: "none",
			expectReasons:       false,
		},
		{
			name: "DMARC fail - reject policy",
			policy: &types.DMARCPolicy{
				Policy: "reject",
			},
			alignment: &types.DMARCAlignmentResult{
				SPFAligned:  false,
				DKIMAligned: false,
			},
			expectedDisposition: "reject",
			expectReasons:       true,
		},
		{
			name: "DMARC fail - quarantine policy",
			policy: &types.DMARCPolicy{
				Policy: "quarantine",
			},
			alignment: &types.DMARCAlignmentResult{
				SPFAligned:  false,
				DKIMAligned: false,
			},
			expectedDisposition: "quarantine",
			expectReasons:       true,
		},
		{
			name: "DMARC fail - none policy",
			policy: &types.DMARCPolicy{
				Policy: "none",
			},
			alignment: &types.DMARCAlignmentResult{
				SPFAligned:  false,
				DKIMAligned: false,
			},
			expectedDisposition: "none",
			expectReasons:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			disposition, reasons := verifier.applyPolicy(tt.policy, tt.alignment)
			assert.Equal(t, tt.expectedDisposition, disposition)
			if tt.expectReasons {
				assert.NotEmpty(t, reasons)
			} else {
				assert.Empty(t, reasons)
			}
		})
	}
}

func TestCalculateScore(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	tests := []struct {
		name          string
		result        *types.DMARCResult
		policy        *types.DMARCPolicy
		alignment     *types.DMARCAlignmentResult
		expectedRange []float64 // [min, max]
	}{
		{
			name: "DMARC pass",
			result: &types.DMARCResult{
				Valid: true,
			},
			policy: &types.DMARCPolicy{
				Policy: "reject",
			},
			alignment:     &types.DMARCAlignmentResult{},
			expectedRange: []float64{-3.0, -1.0}, // Negative score for pass
		},
		{
			name: "DMARC fail - reject policy",
			result: &types.DMARCResult{
				Valid: false,
			},
			policy: &types.DMARCPolicy{
				Policy: "reject",
			},
			alignment:     &types.DMARCAlignmentResult{},
			expectedRange: []float64{8.0, 10.0}, // High penalty for reject
		},
		{
			name: "DMARC fail - none policy",
			result: &types.DMARCResult{
				Valid: false,
			},
			policy: &types.DMARCPolicy{
				Policy: "none",
			},
			alignment:     &types.DMARCAlignmentResult{},
			expectedRange: []float64{2.0, 4.0}, // Lower penalty for monitoring
		},
		{
			name:          "No policy",
			result:        &types.DMARCResult{},
			policy:        nil,
			alignment:     &types.DMARCAlignmentResult{},
			expectedRange: []float64{0.4, 0.6}, // Small penalty for no policy
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := verifier.calculateScore(tt.result, tt.policy, tt.alignment)
			assert.GreaterOrEqual(t, score, tt.expectedRange[0])
			assert.LessOrEqual(t, score, tt.expectedRange[1])
		})
	}
}

func TestGetOrganizationalDomain(t *testing.T) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "example.com",
		},
		{
			name:     "subdomain",
			domain:   "mail.example.com",
			expected: "example.com",
		},
		{
			name:     "deep subdomain",
			domain:   "smtp.mail.example.com",
			expected: "example.com",
		},
		{
			name:     "co.uk domain",
			domain:   "example.co.uk",
			expected: "example.co.uk",
		},
		{
			name:     "subdomain co.uk",
			domain:   "mail.example.co.uk",
			expected: "example.co.uk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.getOrganizationalDomain(tt.domain)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Integration test with mock DNS
func TestVerifyIntegration(t *testing.T) {
	logger := zap.NewNop()
	verifier := NewVerifier(logger, nil, &Config{
		Enabled:  true,
		CacheTTL: 3600,
	})

	// This would require mocking DNS lookups in a real test
	// For now, we test the basic structure

	ctx := context.Background()
	fromDomain := "example.com"

	spfResult := &types.SPFResult{
		Result: "pass",
		Domain: "example.com",
		Score:  -1.0,
	}

	dkimResult := &types.DKIMResult{
		Valid:  true,
		Domain: "example.com",
		AlignmentCandidates: []types.AlignmentCandidate{
			{Domain: "example.com", Valid: true},
		},
		Score: -1.0,
	}

	// This will fail DNS lookup in test environment, but we can check structure
	_, _ = verifier.Verify(ctx, fromDomain, spfResult, dkimResult)
}

// Benchmark tests
func BenchmarkParseDMARCRecord(b *testing.B) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}
	record := "v=DMARC1; p=quarantine; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.parseDMARCRecord(record)
	}
}

func BenchmarkCheckDomainAlignment(b *testing.B) {
	logger := zap.NewNop()
	verifier := &DMARCVerifier{logger: logger}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = verifier.checkDomainAlignment("example.com", "mail.example.com", types.AlignmentRelaxed)
	}
}
