package dkim

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

// Sample real-world DKIM-signed emails for integration testing
var realEmailSamples = map[string]struct {
	email    string
	expected bool
	domain   string
}{
	"valid_gmail": {
		email: `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601;
        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignatureDataHere123456789
From: test@gmail.com
To: recipient@example.com
Subject: Test Email
Date: Thu, 1 Jan 2024 12:00:00 +0000
Message-ID: <test@gmail.com>

Test email body`,
		expected: false, // Will fail due to test signature
		domain:   "gmail.com",
	},
	"multiple_signatures": {
		email: `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=example.com; s=selector1;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignature1
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=example.com; s=selector2;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignature2
From: sender@example.com
To: recipient@example.com
Subject: Multiple Signatures Test

This email has multiple DKIM signatures.`,
		expected: false, // Will fail due to test signatures
		domain:   "example.com",
	},
	"expired_signature": {
		email: `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=expired.com; s=old; x=1577836800;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=ExpiredTestSignature
From: sender@expired.com
To: recipient@example.com
Subject: Expired Signature Test

This email has an expired DKIM signature.`,
		expected: false,
		domain:   "expired.com",
	},
	"weak_hash": {
		email: `DKIM-Signature: v=1; a=rsa-sha1; c=relaxed/relaxed;
        d=weak.com; s=old;
        h=from:to:subject;
        bh=WeakHashExample=;
        b=WeakHashSignature
From: sender@weak.com
To: recipient@example.com
Subject: Weak Hash Test

This email uses SHA-1 hashing.`,
		expected: false,
		domain:   "weak.com",
	},
	"malformed_signature": {
		email: `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=malformed.com; s=bad;
        h=from:to:subject;
        bh=;
        b=
From: sender@malformed.com
To: recipient@example.com
Subject: Malformed Signature Test

This email has malformed signature data.`,
		expected: false,
		domain:   "malformed.com",
	},
}

// TestRealEmailSamples tests DKIM verification with real email samples
func TestRealEmailSamples(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	// Mock DNS lookups for test domains
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		// Return appropriate responses for different test scenarios
		switch {
		case strings.Contains(domain, "gmail.com"):
			return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
		case strings.Contains(domain, "example.com"):
			return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
		case strings.Contains(domain, "expired.com"):
			return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
		case strings.Contains(domain, "weak.com"):
			return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
		case strings.Contains(domain, "malformed.com"):
			return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
		default:
			return nil, 0, fmt.Errorf("no key found for %s", domain)
		}
	}
	defer func() { txtLookup = defaultLookupTXT }()

	for name, sample := range realEmailSamples {
		t.Run(name, func(t *testing.T) {
			result, err := VerifyWithCorrelationID([]byte(sample.email), fmt.Sprintf("integration-test-%s", name))
			
			// We expect the function to not crash and return some result
			if err != nil && result == nil {
				t.Fatalf("verification failed completely: %v", err)
			}

			// Verify that we got detailed information about signatures
			if result.TotalSignatures == 0 {
				t.Error("expected to find at least one signature")
			}

			// Verify domain extraction worked
			if result.Domain != sample.domain && result.TotalSignatures > 0 {
				t.Errorf("expected domain %s, got %s", sample.domain, result.Domain)
			}

			// Verify enhanced features are populated
			if len(result.Signatures) != result.TotalSignatures {
				t.Errorf("signature count mismatch: total=%d, detailed=%d", result.TotalSignatures, len(result.Signatures))
			}

			// Check for edge case detection in problematic samples
			if name == "multiple_signatures" && result.EdgeCaseInfo == nil {
				t.Error("expected edge case detection for multiple signatures")
			}

			// Log detailed results for analysis
			t.Logf("Sample: %s, Valid: %v, Signatures: %d/%d, Score: %f", 
				name, result.Valid, result.ValidSignatures, result.TotalSignatures, result.Score)
		})
	}
}

// TestDMARCIntegration tests DMARC preparation functionality
func TestDMARCIntegration(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	testEmail := []byte(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=subdomain.example.com; s=test;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignature
From: sender@example.com
To: recipient@example.com
Subject: DMARC Alignment Test

Testing DMARC alignment scenarios.`)

       result, err := VerifyForDMARC(testEmail, "example.com", "")
	if err != nil && result == nil {
		t.Fatalf("DMARC verification failed: %v", err)
	}

	// Verify alignment candidates are populated
	if len(result.AlignmentCandidates) == 0 {
		t.Error("expected alignment candidates to be populated")
	}

	// Test alignment checking
	aligned := CheckDMARCAlignment("example.com", result, types.AlignmentRelaxed)
	t.Logf("DMARC alignment (relaxed): %v", aligned)

	strictAligned := CheckDMARCAlignment("example.com", result, types.AlignmentStrict)
	t.Logf("DMARC alignment (strict): %v", strictAligned)
}

// TestDomainExtractionIntegration tests organizational domain extraction with real examples
func TestDomainExtractionIntegration(t *testing.T) {
	realDomains := map[string]string{
		"mail.google.com":        "google.com",
		"smtp.office365.com":     "office365.com",
		"mx.example.co.uk":       "example.co.uk",
		"mail.github.com":        "github.com",
		"outbound.mailchimp.com": "mailchimp.com",
		"send.amazonaws.com":     "amazonaws.com",
		"relay.sendgrid.net":     "sendgrid.net",
		"mta.mailgun.org":        "mailgun.org",
	}

	for input, expected := range realDomains {
		t.Run(input, func(t *testing.T) {
			result := GetOrganizationalDomainDetailed(input)
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.OrgDomain != expected {
				t.Errorf("expected %s, got %s", expected, result.OrgDomain)
			}
			t.Logf("Domain: %s -> OrgDomain: %s, PublicSuffix: %s, Subdomain: %s", 
				input, result.OrgDomain, result.PublicSuffix, result.Subdomain)
		})
	}
}

// TestPerformanceWithRealScenarios tests performance under realistic conditions
func TestPerformanceWithRealScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	// Simulate realistic DNS response times
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		// Simulate network latency
		time.Sleep(10 * time.Millisecond)
		return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	// Test with various email sizes and complexities
	scenarios := []struct {
		name  string
		email []byte
	}{
		{
			name: "simple_email",
			email: []byte(`From: test@example.com
To: recipient@example.com
Subject: Simple Test

Simple body.`),
		},
		{
			name: "complex_email",
			email: []byte(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test; h=from:to:subject:date; bh=hash; b=sig
From: "Complex Sender" <sender@example.com>
To: "Recipient Name" <recipient@example.com>
Subject: =?UTF-8?B?VGVzdCBzdWJqZWN0IHdpdGggVVRGLTg=?=
Date: Thu, 1 Jan 2024 12:00:00 +0000
Message-ID: <complex@example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=UTF-8

Plain text version of the email.

--boundary123
Content-Type: text/html; charset=UTF-8

<html><body><p>HTML version of the email.</p></body></html>

--boundary123--`),
		},
		{
			name: "large_email",
			email: func() []byte {
				body := strings.Repeat("This is a large email body. ", 1000)
				return []byte(fmt.Sprintf(`From: test@example.com
To: recipient@example.com
Subject: Large Email Test

%s`, body))
			}(),
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			start := time.Now()
			result, err := VerifyWithCorrelationID(scenario.email, fmt.Sprintf("perf-test-%s", scenario.name))
			duration := time.Since(start)

			if err != nil && result == nil {
				t.Fatalf("verification failed: %v", err)
			}

			// Performance expectations
			if duration > 5*time.Second {
				t.Errorf("verification took too long: %v", duration)
			}

			t.Logf("Scenario: %s, Duration: %v, Email size: %d bytes", 
				scenario.name, duration, len(scenario.email))
		})
	}
}

// TestErrorRecoveryIntegration tests error recovery and graceful degradation
func TestErrorRecoveryIntegration(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	errorScenarios := map[string]func(context.Context, string) ([]string, uint32, error){
		"dns_timeout": func(ctx context.Context, domain string) ([]string, uint32, error) {
			time.Sleep(50 * time.Millisecond)
			return nil, 0, fmt.Errorf("dns timeout")
		},
		"dns_nxdomain": func(ctx context.Context, domain string) ([]string, uint32, error) {
			return nil, 0, fmt.Errorf("domain not found")
		},
		"invalid_key_record": func(ctx context.Context, domain string) ([]string, uint32, error) {
			return []string{"invalid key data"}, 60, nil
		},
		"empty_response": func(ctx context.Context, domain string) ([]string, uint32, error) {
			return []string{}, 60, nil
		},
	}

	testEmail := []byte(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=error-test.com; s=test;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignature
From: test@error-test.com
To: recipient@example.com
Subject: Error Recovery Test

Testing error recovery scenarios.`)

	for errorType, lookupFunc := range errorScenarios {
		t.Run(errorType, func(t *testing.T) {
			txtLookup = lookupFunc
			defer func() { txtLookup = defaultLookupTXT }()

			result, err := VerifyWithCorrelationID(testEmail, fmt.Sprintf("error-test-%s", errorType))

			// Verify that the system doesn't crash and provides some result
			if result == nil && err == nil {
				t.Error("expected either result or error")
			}

			// Verify graceful degradation
			if result != nil {
				if result.TotalSignatures == 0 {
					t.Error("expected to detect at least one signature even with DNS errors")
				}
				
				// Check that error information is captured
				if len(result.Signatures) > 0 && result.Signatures[0].Error == "" {
					t.Log("Note: Error details not captured in signature result")
				}
			}

			t.Logf("Error scenario: %s, Result valid: %v, Error: %v", 
				errorType, result != nil && result.Valid, err)
		})
	}
}

// TestCacheIntegration tests caching behavior in realistic scenarios
func TestCacheIntegration(t *testing.T) {
	// This test would require Redis setup and is more suitable for integration environment
	// For now, we'll test the cache key generation and basic functionality
	
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	lookupCount := 0
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		lookupCount++
		return []string{"v=DKIM1; k=rsa; p=TestPublicKey"}, 3600, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	testEmail := []byte(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=cache-test.com; s=test;
        h=from:to:subject;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=TestSignature
From: test@cache-test.com
To: recipient@example.com
Subject: Cache Test

Testing cache behavior.`)

	// First verification
	_, err := VerifyWithCorrelationID(testEmail, "cache-test-1")
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}

	firstLookupCount := lookupCount

	// Second verification (should hit cache if enabled)
	_, err = VerifyWithCorrelationID(testEmail, "cache-test-2")
	if err != nil {
		t.Fatalf("second verification failed: %v", err)
	}

	secondLookupCount := lookupCount

	t.Logf("DNS lookups: first=%d, second=%d", firstLookupCount, secondLookupCount)
	
	// Note: Without Redis configured, caching won't work, but the test verifies the code path
}