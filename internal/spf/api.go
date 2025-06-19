package spf

import (
	"context"
	"net"

	"github.com/mail-cci/antispam/internal/types"
)

// Check evaluates SPF for the given IP, domain and sender.
// It returns the resulting SPFResult without performing any caching.
func Check(ctx context.Context, ip net.IP, domain, sender string) (types.SPFResult, error) {
	res := types.SPFResult{Domain: domain}
	r, err := checkSPF(ctx, ip, domain, sender, 0)
	if err != nil {
		return res, err
	}
	res.Result = r
	res.Score = scoreFor(r)
	return res, nil
}
