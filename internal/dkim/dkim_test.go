package dkim

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	godkim "github.com/emersion/go-msgauth/dkim"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
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
