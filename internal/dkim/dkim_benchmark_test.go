package dkim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	godkim "github.com/emersion/go-msgauth/dkim"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

// BenchmarkDKIMVerify benchmarks basic DKIM verification
func BenchmarkDKIMVerify(b *testing.B) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nThis is a test email body.")
	var signed bytes.Buffer
	if err := godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "test",
		Signer:     priv,
		HeaderKeys: []string{"From", "To", "Subject"},
	}); err != nil {
		b.Fatalf("sign failed: %v", err)
	}

	signedEmail := signed.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Verify(signedEmail)
		if err != nil {
			b.Fatalf("verify failed: %v", err)
		}
	}
}

// BenchmarkDKIMVerifyWithCache benchmarks DKIM verification with Redis cache
func BenchmarkDKIMVerifyWithCache(b *testing.B) {
	mr := miniredis.RunT(b)
	cfg := &config.Config{
		RedisURL: mr.Addr(),
		Auth: config.AuthConfig{
			DKIM: config.DKIMConfig{CacheTTL: time.Hour},
		},
	}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	lookupCount := 0
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		lookupCount++
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
		b.Fatalf("sign failed: %v", err)
	}

	signedEmail := signed.Bytes()

	// Warm up cache
	Verify(signedEmail)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Verify(signedEmail)
		if err != nil {
			b.Fatalf("verify failed: %v", err)
		}
	}
}

// BenchmarkMultipleSignatures benchmarks verification of emails with multiple signatures
func BenchmarkMultipleSignatures(b *testing.B) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	pub3, priv3, _ := ed25519.GenerateKey(nil)
	pub1B64 := base64.StdEncoding.EncodeToString(pub1)
	pub2B64 := base64.StdEncoding.EncodeToString(pub2)
	pub3B64 := base64.StdEncoding.EncodeToString(pub3)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		switch domain {
		case "sel1._domainkey.example.com":
			return []string{fmt.Sprintf("v=DKIM1; p=%s", pub1B64)}, 60, nil
		case "sel2._domainkey.example.com":
			return []string{fmt.Sprintf("v=DKIM1; p=%s", pub2B64)}, 60, nil
		case "sel3._domainkey.example.com":
			return []string{fmt.Sprintf("v=DKIM1; p=%s", pub3B64)}, 60, nil
		default:
			return nil, 0, fmt.Errorf("unexpected domain %s", domain)
		}
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\n\r\nbody")

	// Create email with 3 signatures
	var signed1 bytes.Buffer
	godkim.Sign(&signed1, bytes.NewReader(raw), &godkim.SignOptions{
		Domain: "example.com", Selector: "sel1", Signer: priv1, HeaderKeys: []string{"From"},
	})

	var signed2 bytes.Buffer
	godkim.Sign(&signed2, bytes.NewReader(signed1.Bytes()), &godkim.SignOptions{
		Domain: "example.com", Selector: "sel2", Signer: priv2, HeaderKeys: []string{"From"},
	})

	var signed3 bytes.Buffer
	godkim.Sign(&signed3, bytes.NewReader(signed2.Bytes()), &godkim.SignOptions{
		Domain: "example.com", Selector: "sel3", Signer: priv3, HeaderKeys: []string{"From"},
	})

	signedEmail := signed3.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyWithCorrelationID(signedEmail, fmt.Sprintf("bench-%d", i))
		if err != nil {
			b.Fatalf("verify failed: %v", err)
		}
	}
}

// BenchmarkEdgeCaseDetection benchmarks edge case detection functionality
func BenchmarkEdgeCaseDetection(b *testing.B) {
	// Create test signatures with various anomalies
	signatures := make([]types.DKIMSignatureResult, 15) // Trigger "too many signatures"
	for i := range signatures {
		signatures[i] = types.DKIMSignatureResult{
			Valid:    i%3 == 0, // Mix of valid/invalid
			Domain:   fmt.Sprintf("domain%d.com", i%4), // Multiple domains
			Selector: fmt.Sprintf("sel%d", i),
			Headers:  []string{"from", "to"},
			KeyLength: 1024 + (i%2)*1024, // Mix of key lengths
			WeakHash:  i%5 == 0,          // Some weak hashes
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		edgeInfo := detectEdgeCases(signatures)
		if edgeInfo == nil {
			b.Fatal("expected edge case info")
		}
	}
}

// BenchmarkScoring benchmarks the enhanced scoring algorithms
func BenchmarkScoring(b *testing.B) {
	result := &types.DKIMResult{
		Valid:           true,
		TotalSignatures: 5,
		ValidSignatures: 3,
		Signatures: []types.DKIMSignatureResult{
			{Valid: true, Domain: "good1.com", Headers: []string{"from", "to"}, KeyLength: 2048},
			{Valid: true, Domain: "good2.com", Headers: []string{"from", "subject"}, KeyLength: 2048},
			{Valid: true, Domain: "good3.com", Headers: []string{"from"}, KeyLength: 1024},
			{Valid: false, Domain: "bad1.com", Error: "key unavailable"},
			{Valid: false, Domain: "bad2.com", Error: "signature has expired"},
		},
		EdgeCaseInfo: &types.DKIMEdgeCaseInfo{
			Anomalies:   []types.DKIMAnomalyFlag{types.AnomalyMultipleValidDomains},
			ThreatLevel: types.ThreatLow,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		score := calculateEnhancedScoreWithDegradation(result)
		_ = score
	}
}

// BenchmarkOrganizationalDomainExtraction benchmarks domain extraction
func BenchmarkOrganizationalDomainExtraction(b *testing.B) {
	domains := []string{
		"example.com",
		"mail.example.com",
		"deep.subdomain.example.com",
		"test.co.uk",
		"mail.google.com",
		"support.github.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domain := domains[i%len(domains)]
		result := GetOrganizationalDomainDetailed(domain)
		_ = result
	}
}

// BenchmarkConcurrentVerification benchmarks concurrent DKIM verification
func BenchmarkConcurrentVerification(b *testing.B) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		// Simulate network latency
		time.Sleep(time.Millisecond)
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	var signed bytes.Buffer
	godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "test",
		Signer:     priv,
		HeaderKeys: []string{"From"},
	})

	signedEmail := signed.Bytes()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := Verify(signedEmail)
			if err != nil {
				b.Fatalf("verify failed: %v", err)
			}
		}
	})
}

// BenchmarkLoadTest simulates high-volume email processing
func BenchmarkLoadTest(b *testing.B) {
	mr := miniredis.RunT(b)
	cfg := &config.Config{
		RedisURL: mr.Addr(),
		Auth: config.AuthConfig{
			DKIM: config.DKIMConfig{CacheTTL: time.Hour},
		},
	}
	Init(cfg, zap.NewNop())

	// Create multiple key pairs for different domains
	keyPairs := make(map[string]struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	})

	domains := []string{"domain1.com", "domain2.com", "domain3.com", "domain4.com"}
	for _, domain := range domains {
		pub, priv, _ := ed25519.GenerateKey(nil)
		keyPairs[domain] = struct {
			pub  ed25519.PublicKey
			priv ed25519.PrivateKey
		}{pub, priv}
	}

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		for _, d := range domains {
			if domain == fmt.Sprintf("test._domainkey.%s", d) {
				pub := keyPairs[d].pub
				pubB64 := base64.StdEncoding.EncodeToString(pub)
				return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
			}
		}
		return nil, 0, fmt.Errorf("unknown domain %s", domain)
	}
	defer func() { txtLookup = defaultLookupTXT }()

	// Pre-create signed emails for different domains
	signedEmails := make([][]byte, len(domains))
	for i, domain := range domains {
		raw := []byte(fmt.Sprintf("From: sender@%s\r\nSubject: Test %d\r\n\r\nbody", domain, i))
		var signed bytes.Buffer
		godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
			Domain:     domain,
			Selector:   "test",
			Signer:     keyPairs[domain].priv,
			HeaderKeys: []string{"From", "Subject"},
		})
		signedEmails[i] = signed.Bytes()
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var counter int
		for pb.Next() {
			email := signedEmails[counter%len(signedEmails)]
			_, err := VerifyWithCorrelationID(email, fmt.Sprintf("load-test-%d", counter))
			if err != nil {
				b.Fatalf("verify failed: %v", err)
			}
			counter++
		}
	})
}

// TestDKIMLoadStress performs stress testing with error scenarios
func TestDKIMLoadStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	// Simulate various error conditions
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		switch {
		case domain == "timeout._domainkey.example.com":
			time.Sleep(100 * time.Millisecond)
			return nil, 0, fmt.Errorf("timeout")
		case domain == "nokey._domainkey.example.com":
			return nil, 0, fmt.Errorf("no key found")
		case domain == "invalid._domainkey.example.com":
			return []string{"invalid key data"}, 60, nil
		default:
			return []string{"v=DKIM1; p=invalid"}, 60, nil
		}
	}
	defer func() { txtLookup = defaultLookupTXT }()

	scenarios := [][]byte{
		[]byte("From: sender@example.com\r\n\r\nbody"), // No signature
		[]byte("DKIM-Signature: v=1; a=rsa-sha256; d=timeout.com; s=timeout\r\nFrom: sender@timeout.com\r\n\r\nbody"),
		[]byte("DKIM-Signature: v=1; a=rsa-sha256; d=nokey.com; s=nokey\r\nFrom: sender@nokey.com\r\n\r\nbody"),
		[]byte("DKIM-Signature: v=1; a=rsa-sha256; d=invalid.com; s=invalid\r\nFrom: sender@invalid.com\r\n\r\nbody"),
	}

	const numGoroutines = 10
	const emailsPerGoroutine = 100

	var wg sync.WaitGroup
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < emailsPerGoroutine; j++ {
				email := scenarios[j%len(scenarios)]
				correlationID := fmt.Sprintf("stress-%d-%d", goroutineID, j)
				
				start := time.Now()
				result, err := VerifyWithCorrelationID(email, correlationID)
				duration := time.Since(start)
				
				// Verify that we get some result, even if invalid
				if result == nil && err == nil {
					t.Errorf("expected either result or error for goroutine %d, email %d", goroutineID, j)
				}
				
				// Check for reasonable performance (should complete within 1 second)
				if duration > time.Second {
					t.Errorf("verification took too long: %v for goroutine %d, email %d", duration, goroutineID, j)
				}
			}
		}(i)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("Stress test completed successfully with %d goroutines, %d emails each", numGoroutines, emailsPerGoroutine)
	case <-time.After(30 * time.Second):
		t.Fatal("Stress test timed out after 30 seconds")
	}
}

// BenchmarkMemoryUsage benchmarks memory allocation patterns
func BenchmarkMemoryUsage(b *testing.B) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	pub, priv, _ := ed25519.GenerateKey(nil)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		return []string{fmt.Sprintf("v=DKIM1; p=%s", pubB64)}, 60, nil
	}
	defer func() { txtLookup = defaultLookupTXT }()

	raw := []byte("From: sender@example.com\r\nSubject: Memory Test\r\n\r\nThis is a test for memory usage patterns.")
	var signed bytes.Buffer
	godkim.Sign(&signed, bytes.NewReader(raw), &godkim.SignOptions{
		Domain:     "example.com",
		Selector:   "test",
		Signer:     priv,
		HeaderKeys: []string{"From", "Subject"},
	})

	signedEmail := signed.Bytes()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := Verify(signedEmail)
		if err != nil {
			b.Fatalf("verify failed: %v", err)
		}
		_ = result
	}
}