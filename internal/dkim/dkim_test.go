package dkim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/mail"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	godkim "github.com/emersion/go-msgauth/dkim"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
	"github.com/mail-cci/antispam/internal/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	_, _ = Verify(raw)
}

func TestVerifyCacheHitMiss(t *testing.T) {
	mr := miniredis.RunT(t)
	cfg := &config.Config{RedisURL: mr.Addr(), Auth: config.AuthConfig{DKIM: config.DKIMConfig{CacheTTL: time.Minute}}}
	Init(cfg, zap.NewNop())

	// generate signing key
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	lookupCount := 0
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		lookupCount++
		if domain != "test._domainkey.example.com" {
			return nil, 0, fmt.Errorf("unexpected domain %s", domain)
		}
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	// sign a simple message
	raw := []byte("From: sender@example.com\r\n\r\nbody")
	var signed bytes.Buffer
	err := godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "test",
		Signer:     priv,
		HeaderKeys: []string{"From"},
	})
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	startTotal := testutil.ToFloat64(metrics.DKIMChecksTotal)

	// first verification - miss
	_, err = Verify(signed.Bytes())
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if lookupCount != 1 {
		t.Errorf("expected lookup count 1, got %d", lookupCount)
	}
	if _, err := mr.Get("dkim:key:test:example.com"); err != nil {
		t.Errorf("key not cached: %v", err)
	}

	// second verification - hit
	_, err = Verify(signed.Bytes())
	if err != nil {
		t.Fatalf("second verify failed: %v", err)
	}
	if lookupCount != 1 {
		t.Errorf("expected cache hit, lookup not performed")
	}

	if diff := testutil.ToFloat64(metrics.DKIMChecksTotal) - startTotal; diff != 2 {
		t.Errorf("expected DKIMChecksTotal increase by 2, got %v", diff)
	}
}

func TestVerifySelectorParsing(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		if domain != "test._domainkey.example.com" {
			return nil, 0, fmt.Errorf("unexpected domain %s", domain)
		}
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	var signed bytes.Buffer
	if err := godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "test",
		Signer:     priv,
		HeaderKeys: []string{"From"},
	}); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	res, err := Verify(signed.Bytes())
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if res.Selector != "test" {
		t.Errorf("expected selector 'test', got %s", res.Selector)
	}
}

func TestVerifyInvalidSelector(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		if domain != "bad*sel._domainkey.example.com" {
			return nil, 0, fmt.Errorf("unexpected domain %s", domain)
		}
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	var signed bytes.Buffer
	if err := godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "bad*sel",
		Signer:     priv,
		HeaderKeys: []string{"From"},
	}); err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(signed.Bytes()))
	if err != nil {
		t.Fatalf("failed to parse signed message: %v", err)
	}
	header := msg.Header.Get("DKIM-Signature")
	if header == "" {
		t.Fatal("missing DKIM-Signature header")
	}
	_, err = parseSelector(header)
	if err == nil {
		t.Fatal("expected selector parsing error")
	}
	code := errorCodeFromError(err)
	if code != DKIM_SIGERROR_EMPTY_S {
		t.Errorf("expected error code %d, got %d", DKIM_SIGERROR_EMPTY_S, code)
	}
}

// TestMultipleSignatures tests enhanced DKIM verification with multiple signatures
func TestMultipleSignatures(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	pub1B64 := base64.StdEncoding.EncodeToString(pub1)
	pub2B64 := base64.StdEncoding.EncodeToString(pub2)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		switch domain {
		case "sel1._domainkey.example.com":
			return []string{fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", pub1B64)}, 60, nil
		case "sel2._domainkey.example.com":
			return []string{fmt.Sprintf("v=DKIM1; k=ed25519; p=%s", pub2B64)}, 60, nil
		default:
			return nil, 0, fmt.Errorf("unexpected domain %s", domain)
		}
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\n\r\nbody")

	// First signature
	var signed1 bytes.Buffer
	if err := godkim.Sign(&signed1, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "sel1",
		Signer:     priv1,
		HeaderKeys: []string{"From"},
	}); err != nil {
		t.Fatalf("first sign failed: %v", err)
	}

	// Second signature on the already signed message
	var signed2 bytes.Buffer
	if err := godkim.Sign(&signed2, bytes.NewReader(signed1.Bytes()), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "sel2",
		Signer:     priv2,
		HeaderKeys: []string{"From"},
	}); err != nil {
		t.Fatalf("second sign failed: %v", err)
	}

	res, err := VerifyWithCorrelationID(signed2.Bytes(), "test-correlation-123")
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	if !res.Valid {
		t.Error("expected valid result")
	}
	if res.TotalSignatures != 2 {
		t.Errorf("expected 2 signatures, got %d", res.TotalSignatures)
	}
	if res.ValidSignatures != 2 {
		t.Errorf("expected 2 valid signatures, got %d", res.ValidSignatures)
	}
	if len(res.Signatures) != 2 {
		t.Errorf("expected 2 signature results, got %d", len(res.Signatures))
	}
	if len(res.AlignmentCandidates) != 2 {
		t.Errorf("expected 2 alignment candidates, got %d", len(res.AlignmentCandidates))
	}
	if res.BestSignature == nil {
		t.Error("expected best signature to be selected")
	}
	if res.Score >= 0 {
		t.Errorf("expected negative score for valid signatures, got %f", res.Score)
	}

	if !res.DomainAgreement {
		t.Error("expected domain agreement")
	}
	if res.SelectorReuse {
		t.Error("unexpected selector reuse detected")
	}
	if !res.RolloverDetected {
		t.Error("expected rollover detection")
	}
}

// TestEdgeCaseDetection tests the edge case detection functionality
func TestEdgeCaseDetection(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	testCases := []struct {
		name           string
		signatures     []godkim.SignOptions
		expectedAnoms  int
		expectedThreat string
	}{
		{
			name:           "too_many_signatures",
			signatures:     make([]godkim.SignOptions, 12), // More than 10
			expectedAnoms:  1,
			expectedThreat: "low",
		},
		{
			name: "mixed_domains",
			signatures: []godkim.SignOptions{
				{Domain: "example.com", Selector: "sel1"},
				{Domain: "different.com", Selector: "sel2"},
				{Domain: "another.com", Selector: "sel3"},
			},
			expectedAnoms:  1,
			expectedThreat: "low",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// For too_many_signatures test, initialize all signatures
			if tc.name == "too_many_signatures" {
				for i := range tc.signatures {
					tc.signatures[i] = godkim.SignOptions{
						Domain:     "example.com",
						Selector:   fmt.Sprintf("sel%d", i),
						HeaderKeys: []string{"From"},
					}
				}
			}

			// Create mock signatures for testing
			var signatures []types.DKIMSignatureResult
			for _, sig := range tc.signatures {
				signatures = append(signatures, types.DKIMSignatureResult{
					Domain:   sig.Domain,
					Selector: sig.Selector,
					Valid:    true,
					Headers:  sig.HeaderKeys,
				})
			}

			edgeInfo := detectEdgeCases(signatures)
			if edgeInfo == nil {
				t.Fatal("expected edge case info")
			}

			if len(edgeInfo.Anomalies) < tc.expectedAnoms {
				t.Errorf("expected at least %d anomalies, got %d", tc.expectedAnoms, len(edgeInfo.Anomalies))
			}
		})
	}
}

// TestOrganizationalDomainExtraction tests domain extraction functionality
func TestOrganizationalDomainExtraction(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"example.co.uk", "example.co.uk"},
		{"sub.example.co.uk", "example.co.uk"},
		{"test.gov.uk", "test.gov.uk"},
		{"mail.google.com", "google.com"},
		{"", ""},
		{"invalid", "invalid"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := GetOrganizationalDomainDetailed(tc.input)
			if result == nil && tc.input != "" {
				t.Fatal("expected non-nil result")
			}
			if result != nil && result.OrgDomain != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result.OrgDomain)
			}
		})
	}
}

// TestDMARCAlignment tests DMARC alignment functionality
func TestDMARCAlignment(t *testing.T) {
	testCases := []struct {
		name       string
		fromDomain string
		sigDomain  string
		mode       types.DMARCAlignmentMode
		valid      bool
		expected   bool
	}{
		{"strict_exact_match", "example.com", "example.com", types.AlignmentStrict, true, true},
		{"strict_subdomain_fail", "example.com", "mail.example.com", types.AlignmentStrict, true, false},
		{"relaxed_exact_match", "example.com", "example.com", types.AlignmentRelaxed, true, true},
		{"relaxed_subdomain_pass", "example.com", "mail.example.com", types.AlignmentRelaxed, true, true},
		{"relaxed_different_org_fail", "example.com", "different.com", types.AlignmentRelaxed, true, false},
		{"invalid_signature", "example.com", "example.com", types.AlignmentStrict, false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dkimResult := &types.DKIMResult{
				Valid:  tc.valid,
				Domain: tc.sigDomain,
			}

			result := CheckDMARCAlignment(tc.fromDomain, dkimResult, tc.mode)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

// TestSignatureScoring tests the signature quality scoring
func TestSignatureScoring(t *testing.T) {
	testCases := []struct {
		name      string
		signature types.DKIMSignatureResult
		expected  float64
	}{
		{
			name: "valid_strong_signature",
			signature: types.DKIMSignatureResult{
				Valid:      true,
				WeakHash:   false,
				Headers:    []string{"from", "to", "subject", "date"},
				KeyLength:  2048,
				Expiration: 0,
			},
			expected: 17.4, // 10 + 5 + 0.4 + 2 + 1
		},
		{
			name: "invalid_weak_signature",
			signature: types.DKIMSignatureResult{
				Valid:     false,
				WeakHash:  true,
				Headers:   []string{"from"},
				KeyLength: 1024,
			},
			expected: 1.1, // 0 + 0 + 0.1 + 1 + 0
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			score := scoreSignatureQuality(&tc.signature)
			if score != tc.expected {
				t.Errorf("expected score %f, got %f", tc.expected, score)
			}
		})
	}
}

// TestGracefulDegradation tests graceful degradation for partial failures
func TestGracefulDegradation(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	// Test with mixed results: some valid, some invalid signatures
	result := &types.DKIMResult{
		Valid:           true,
		TotalSignatures: 3,
		ValidSignatures: 1,
		Signatures: []types.DKIMSignatureResult{
			{Valid: true, Domain: "good.com", Headers: []string{"from", "to"}},
			{Valid: false, Domain: "bad.com", Error: "key unavailable", Headers: []string{"from"}},
			{Valid: false, Domain: "expired.com", Error: "signature has expired", Headers: []string{"from", "date"}},
		},
	}

	score := calculateEnhancedScoreWithDegradation(result)
	if score >= 0 {
		t.Errorf("expected negative score for mixed results with valid signature, got %f", score)
	}

	// Test with all invalid signatures
	result.Valid = false
	result.ValidSignatures = 0
	for i := range result.Signatures {
		result.Signatures[i].Valid = false
	}

	score = calculateEnhancedScoreWithDegradation(result)
	if score <= 0 {
		t.Errorf("expected positive score for all invalid signatures, got %f", score)
	}
}

// TestErrorMapping tests DKIM error code mapping
func TestErrorMapping(t *testing.T) {
	testCases := []struct {
		error        string
		expectedCode int
		expectedCat  string
		expectedSev  string
	}{
		{"empty selector", DKIM_SIGERROR_EMPTY_S, "selector", "high"},
		{"signature has expired", DKIM_SIGERROR_EXPIRED, "timing", "medium"},
		{"no valid key found", DKIM_SIGERROR_NOREC, "key_lookup", "high"},
		{"body hash did not verify", DKIM_SIGERROR_BADSIG, "verification", "critical"},
		{"hash algorithm too weak", DKIM_SIGERROR_INVALID_A, "algorithm", "critical"},
		{"unknown error message", DKIM_SIGERROR_UNKNOWN, "unknown", "medium"},
	}

	for _, tc := range testCases {
		t.Run(tc.error, func(t *testing.T) {
			err := fmt.Errorf(tc.error)
			code := errorCodeFromError(err)
			if code != tc.expectedCode {
				t.Errorf("expected error code %d, got %d", tc.expectedCode, code)
			}

			info := getErrorInfo(err)
			if info == nil {
				t.Fatal("expected error info")
			}
			if info.Category != tc.expectedCat {
				t.Errorf("expected category %s, got %s", tc.expectedCat, info.Category)
			}
			if info.Severity != tc.expectedSev {
				t.Errorf("expected severity %s, got %s", tc.expectedSev, info.Severity)
			}
		})
	}
}

// TestSignatureComparison verifies domain agreement, selector reuse and rollover detection
func TestSignatureComparison(t *testing.T) {
	sigs1 := []types.DKIMSignatureResult{
		{Domain: "example.com", Selector: "s1", Valid: true},
		{Domain: "example.com", Selector: "s2", Valid: true},
	}
	if !signaturesDomainAgreement(sigs1) {
		t.Error("expected domain agreement for sigs1")
	}
	if signaturesSelectorReuse(sigs1) {
		t.Error("did not expect selector reuse for sigs1")
	}
	if !signaturesRolloverDetected(sigs1) {
		t.Error("expected rollover for sigs1")
	}

	sigs2 := []types.DKIMSignatureResult{
		{Domain: "a.com", Selector: "s", Valid: true},
		{Domain: "b.com", Selector: "s", Valid: true},
	}
	if signaturesDomainAgreement(sigs2) {
		t.Error("expected domain disagreement for sigs2")
	}
	if !signaturesSelectorReuse(sigs2) {
		t.Error("expected selector reuse for sigs2")
	}
	if signaturesRolloverDetected(sigs2) {
		t.Error("did not expect rollover for sigs2")
	}
}
