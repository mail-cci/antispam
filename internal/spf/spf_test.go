package spf

import (
	"context"
	"net"
	"testing"

	"github.com/mail-cci/antispam/internal/config"
)

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	// Verify relies on the default resolver from the wttw/spf library which
	// performs real DNS lookups. Just ensure the function executes without
	// crashing when Redis is nil.
	_, _ = Verify(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}
