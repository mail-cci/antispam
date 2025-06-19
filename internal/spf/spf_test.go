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

	_, _ = Verify(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}

func TestCheck(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	_, _ = Check(context.Background(), net.ParseIP("127.0.0.1"), "example.com", "user@example.com")
}
