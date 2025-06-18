package spf

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-redis/redis/v8"
	mdns "github.com/miekg/dns"
	"github.com/wttw/spf"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/types"
)

var cfg *config.Config
var rdb *redis.Client

// Init configures the SPF verifier with application settings and
// initializes the redis client. It can be called multiple times safely.
func Init(c *config.Config) {
	cfg = c
	if cfg == nil || cfg.RedisURL == "" {
		rdb = nil
		return
	}
	rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisURL})
}

func scoreFor(result string) float64 {
	switch strings.ToLower(result) {
	case "pass":
		return -1
	case "fail":
		return 5
	case "softfail":
		return 2
	case "neutral":
		return 0.5
	case "temperror":
		return 1
	default:
		return 0
	}
}

// Verify checks the SPF record for the given sender using go-msgauth.
// It returns the SPF result along with a score mapped from that result.
func Verify(ctx context.Context, clientIP net.IP, domain, sender string) (*types.SPFResult, error) {
	res := &types.SPFResult{Domain: domain}

	// attempt cache lookup
	cacheKey := fmt.Sprintf("spf:%s:%s", clientIP.String(), domain)
	if rdb != nil {
		if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
			res.Result = val
			res.Score = scoreFor(val)
			return res, nil
		}
	}

	timeout := cfg.Auth.SPF.Timeout
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	checker := spf.NewChecker()
	r := checker.CheckHost(cctx, clientIP, mdns.Fqdn(domain), sender, "")
	if r.Error != nil {
		return nil, r.Error
	}

	res.Result = r.Type.String()
	res.Explanation = r.Explanation
	res.Score = scoreFor(res.Result)

	if rdb != nil {
		_ = rdb.Set(ctx, cacheKey, res.Result, cfg.Auth.SPF.CacheTTL).Err()
	}

	return res, nil
}
