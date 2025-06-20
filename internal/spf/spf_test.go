package spf

import (
	"context"
	"net"
	"testing"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"
)

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	_, _ = Verify(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}

func TestCheck(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	_, _ = Check(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}

func TestTTLMinimumInclude(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	// stub TXT lookups
	oldLookup := txtLookup
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		switch domain {
		case "parent.test":
			return []string{"v=spf1 include:child.test -all"}, 3600, nil
		case "child.test":
			return []string{"v=spf1 +all"}, 600, nil
		default:
			return nil, 0, nil
		}
	}
	defer func() { txtLookup = oldLookup }()

	res, err := Check(context.Background(), net.ParseIP("1.2.3.4"), "parent.test", "user@parent.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RecordTTL != 600 {
		t.Errorf("expected TTL 600, got %d", res.RecordTTL)
	}
}

func TestTTLMinimumRedirect(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	oldLookup := txtLookup
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		switch domain {
		case "parent2.test":
			return []string{"v=spf1 redirect:child2.test"}, 1200, nil
		case "child2.test":
			return []string{"v=spf1 +all"}, 300, nil
		default:
			return nil, 0, nil
		}
	}
	defer func() { txtLookup = oldLookup }()

	res, err := Check(context.Background(), net.ParseIP("1.2.3.4"), "parent2.test", "user@parent2.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RecordTTL != 300 {
		t.Errorf("expected TTL 300, got %d", res.RecordTTL)
	}
}

func TestVerifyMetrics(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	oldLookup := txtLookup
	txtLookup = func(ctx context.Context, domain string) ([]string, uint32, error) {
		return []string{"v=spf1 +all"}, 300, nil
	}
	defer func() { txtLookup = oldLookup }()

	startTotal := testutil.ToFloat64(metrics.SPFChecksTotal)
	startPass := testutil.ToFloat64(metrics.SPFCheckPass)
	startFail := testutil.ToFloat64(metrics.SPFCheckFail)

	_, err := Verify(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if diff := testutil.ToFloat64(metrics.SPFChecksTotal) - startTotal; diff != 1 {
		t.Errorf("expected SPFChecksTotal to increase by 1, got %v", diff)
	}
	if diff := testutil.ToFloat64(metrics.SPFCheckPass) - startPass; diff != 1 {
		t.Errorf("expected SPFCheckPass to increase by 1, got %v", diff)
	}
	if diff := testutil.ToFloat64(metrics.SPFCheckFail) - startFail; diff != 0 {
		t.Errorf("expected SPFCheckFail unchanged, got increase %v", diff)
	}
}
