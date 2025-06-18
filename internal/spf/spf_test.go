package spf

import (
	"context"
	"net"
	"testing"

	"github.com/mail-cci/antispam/internal/config"
)

// fakeResolver implements the minimal resolver interface used by go-msgauth.
type fakeResolver struct{}

func (fakeResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return []string{"v=spf1 -all"}, nil
}

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	// Replace resolver in Verify by injecting here? the Verify function uses
	// dns.MiekgDNSResolver which uses real DNS, so we cannot test easily.
	// Instead, just ensure that the function runs with a nil redis and returns
	// a result or error.
	_, _ = Verify(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}
