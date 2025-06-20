package spf

import (
	"context"
	"net"

	"github.com/mail-cci/antispam/internal/types"
)

// Check evaluates SPF for the given IP, domain and sender.
// It returns an SPFResult without performing any caching. The RecordTTL field
// contains the minimum TTL observed while evaluating the domain and any
// included or redirected SPF records.
func Check(ctx context.Context, ip net.IP, domain, sender string) (types.SPFResult, error) {
	res := types.SPFResult{Domain: domain}
	r, ttl, err := checkSPF(ctx, ip, domain, sender, 0)
	if err != nil {
		return res, err
	}
	res.Result = r
	if ttl > 0 {
		res.RecordTTL = ttl
	} else {
		res.RecordTTL = 3600 // Default TTL if not provided
	}
	res.Score = scoreFor(r)
	return res, nil
}
