package dkim

import "testing"
import "github.com/mail-cci/antispam/internal/config"

func TestVerify(t *testing.T) {
	cfg := &config.Config{}
	Init(cfg)

	raw := []byte("From: sender@example.com\r\n\r\nbody")
	_, _ = Verify(raw)
}
