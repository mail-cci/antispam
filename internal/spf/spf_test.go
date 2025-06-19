package spf

import (
	"context"
	"net"
	"testing"

	"github.com/mail-cci/antispam/internal/config"
	"go.uber.org/zap"
)

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	_, _ = Verify(zap.NewNop(), context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}

func TestCheck(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	_, _ = Check(zap.NewNop(), context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}

func TestTTLMinimumInclude(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

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

	res, err := Check(zap.NewNop(), context.Background(), net.ParseIP("1.2.3.4"), "parent.test", "user@parent.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RecordTTL != 600 {
		t.Errorf("expected TTL 600, got %d", res.RecordTTL)
	}
}

func TestTTLMinimumRedirect(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

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

	res, err := Check(zap.NewNop(), context.Background(), net.ParseIP("1.2.3.4"), "parent2.test", "user@parent2.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RecordTTL != 300 {
		t.Errorf("expected TTL 300, got %d", res.RecordTTL)
	}
}
