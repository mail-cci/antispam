package dkim

import (
	"github.com/mail-cci/antispam/internal/config"
	"go.uber.org/zap"
	"testing"
)

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg, zap.NewNop())

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	_, _ = Verify(raw)
}
