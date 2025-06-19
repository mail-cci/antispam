package spf

import (
	"context"
	"go.uber.org/zap"
	"net"

	"github.com/mail-cci/antispam/internal/types"
)

// Check evaluates SPF for the given IP, domain and sender.
// It returns the resulting SPFResult without performing any caching.
func Check(logger *zap.Logger, ctx context.Context, ip net.IP, domain, sender string) (types.SPFResult, error) {
	res := types.SPFResult{Domain: domain}
	r, err := checkSPF(logger, ctx, ip, domain, sender, 0)
	if err != nil {
		return res, err
	}
	res.Result = r
	res.Score = scoreFor(r)
	logger.Debug("SPF check result",
		zap.String("domain", domain),
		zap.String("sender", sender),
		zap.String("result", res.Result),
		zap.Float64("score", res.Score),
		zap.String("ip", ip.String()),
	)
	return res, nil
}
