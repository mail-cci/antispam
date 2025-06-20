package spf

import (
	"context"
	"fmt"
	"go.uber.org/zap"
	"net"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
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

// Verify checks the SPF record for the given sender using new Go implementation.
// It returns the SPF result along with a score mapped from that result.
func Verify(logger *zap.Logger, ctx context.Context, clientIP net.IP, domain, sender string) (*types.SPFResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("SPF verification not initialized")
	}

	start := time.Now()
	metrics.SPFChecksTotal.Inc()

	res := &types.SPFResult{Domain: domain}

	// attempt cache lookup
	cacheKey := fmt.Sprintf("spf:%s:%s", clientIP.String(), domain)
	if rdb != nil {
		if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
			res.Result = val
			res.Score = scoreFor(val)
			logger.Debug("SPF cache hit", zap.String("key", cacheKey), zap.String("result", res.Result))
			if strings.ToLower(val) == "pass" {
				metrics.SPFCheckPass.Inc()
			} else {
				metrics.SPFCheckFail.Inc()
			}
			metrics.SPFCheckDurationSeconds.Observe(time.Since(start).Seconds())
			return res, nil
		}
	}

	timeout := cfg.Auth.SPF.Timeout
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r, err := Check(logger, cctx, clientIP, domain, sender)
	if err != nil {
		metrics.SPFCheckFail.Inc()
		metrics.SPFCheckDurationSeconds.Observe(time.Since(start).Seconds())
		return nil, err
	}

	res.Result = r.Result
	res.Explanation = r.Explanation
	res.Score = r.Score
	res.RecordTTL = r.RecordTTL

	if rdb != nil {
		_ = rdb.Set(ctx, cacheKey, res.Result, time.Duration(r.RecordTTL)*time.Second).Err()
	}

	if strings.ToLower(res.Result) == "pass" {
		metrics.SPFCheckPass.Inc()
	} else {
		metrics.SPFCheckFail.Inc()
	}
	metrics.SPFCheckDurationSeconds.Observe(time.Since(start).Seconds())

	return res, nil
}
