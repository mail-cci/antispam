package dkim

import (
	"bytes"
	"context"
	"net"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

var (
	cfg    *config.Config
	logger *zap.Logger
)

// Init stores the application config for DKIM verification.
func Init(c *config.Config, l *zap.Logger) {
	cfg = c
	logger = l
}

func scoreFor(valid bool) float64 {
	if valid {
		return -1
	}
	return 3
}

// Verify checks all DKIM signatures in the provided raw email. It returns a
// DKIMResult with Valid=true if at least one signature verifies correctly.
func Verify(rawEmail []byte) (*types.DKIMResult, error) {
	res := &types.DKIMResult{}
	if logger != nil {
		logger.Debug("verifying DKIM", zap.Int("size", len(rawEmail)))
	}

	// Setup a context with timeout for DNS lookups if configured.
	ctx := context.Background()
	if cfg != nil && cfg.Auth.DKIM.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Auth.DKIM.Timeout)
		defer cancel()
	}

	// Use VerifyWithOptions so DNS queries respect the context timeout.
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(rawEmail), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return net.DefaultResolver.LookupTXT(ctx, domain)
		},
	})
	if err != nil && len(verifs) == 0 {
		return nil, err
	}

	if len(verifs) == 0 {
		// No signatures present.
		res.Valid = false
		res.Score = 0
		return res, nil
	}

	for _, v := range verifs {
		if res.Domain == "" {
			res.Domain = v.Domain
		}
		if v.Err == nil {
			res.Valid = true
		}
	}

	res.Score = scoreFor(res.Valid)
	if logger != nil {
		logger.Debug("dkim verification complete",
			zap.Bool("valid", res.Valid),
			zap.String("domain", res.Domain),
		)
	}
	return res, nil
}
