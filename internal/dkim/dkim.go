package dkim

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/go-redis/redis/v8"
	mdns "github.com/miekg/dns"

	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/metrics"
	"github.com/mail-cci/antispam/internal/types"
	"go.uber.org/zap"
)

var (
	cfg    *config.Config
	rdb    *redis.Client
	logger *zap.Logger
)

var txtLookup = defaultLookupTXT

const (
	dkimSigerrorEmptyS = 18
)

func defaultLookupTXT(ctx context.Context, domain string) ([]string, uint32, error) {
	conf, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(conf.Servers) == 0 {
		return nil, 0, err
	}
	server := net.JoinHostPort(conf.Servers[0], conf.Port)
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeTXT)
	r, _, err := new(mdns.Client).ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, 0, err
	}
	var out []string
	var ttl uint32
	for _, ans := range r.Answer {
		if t, ok := ans.(*mdns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
			if ttl == 0 || t.Hdr.Ttl < ttl {
				ttl = t.Hdr.Ttl
			}
		}
	}
	return out, ttl, nil
}

// Init stores the application config for DKIM verification.
func Init(c *config.Config, l *zap.Logger) {
	cfg = c
	logger = l
	if cfg != nil && cfg.RedisURL != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisURL})
	} else {
		rdb = nil
	}
}

func scoreFor(valid bool) float64 {
	if valid {
		return -1
	}
	return 3
}

var selectorRegexp = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func parseSelector(header string) (string, error) {
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "s=") {
			val := strings.TrimSpace(strings.TrimPrefix(part, "s="))
			if val == "" {
				return "", fmt.Errorf("empty selector")
			}
			if !selectorRegexp.MatchString(val) {
				return "", fmt.Errorf("invalid selector")
			}
			return val, nil
		}
	}
	return "", fmt.Errorf("s tag not found")
}

// Verify checks all DKIM signatures in the provided raw email. It returns a
// DKIMResult with Valid=true if at least one signature verifies correctly.
func Verify(rawEmail []byte) (*types.DKIMResult, error) {
	res := &types.DKIMResult{}
	if logger != nil {
		logger.Debug("verifying DKIM", zap.Int("size", len(rawEmail)))
	}

	// Parse headers to extract selectors from DKIM or ARC signatures
	if msg, err := mail.ReadMessage(bytes.NewReader(rawEmail)); err == nil {
		process := func(values []string) {
			for _, v := range values {
				sel, err := parseSelector(v)
				if err != nil {
					if logger != nil {
						logger.Error("invalid DKIM selector", zap.Int("code", dkimSigerrorEmptyS), zap.Error(err))
					}
					continue
				}
				if res.Selector == "" {
					res.Selector = sel
				}
			}
		}
		dkHeader := textproto.CanonicalMIMEHeaderKey("DKIM-Signature")
		arcHeader := textproto.CanonicalMIMEHeaderKey("ARC-Message-Signature")
		process(msg.Header[dkHeader])
		process(msg.Header[arcHeader])
	}

	start := time.Now()
	metrics.DKIMChecksTotal.Inc()

	// Setup a context with timeout for DNS lookups if configured.
	ctx := context.Background()
	if cfg != nil && cfg.Auth.DKIM.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Auth.DKIM.Timeout)
		defer cancel()
	}

	lookup := func(domain string) ([]string, error) {
		return lookupTXTWithCache(ctx, domain)
	}

	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(rawEmail), &dkim.VerifyOptions{
		LookupTXT: lookup,
	})
	if err != nil && len(verifs) == 0 {
		metrics.DKIMCheckFail.Inc()
		metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())
		return nil, err
	}

	if len(verifs) == 0 {
		res.Valid = false
		res.Score = 0
		metrics.DKIMCheckFail.Inc()
		metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())
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
	if res.Valid {
		metrics.DKIMCheckPass.Inc()
	} else {
		metrics.DKIMCheckFail.Inc()
	}
	metrics.DKIMCheckDurationSeconds.Observe(time.Since(start).Seconds())

	if logger != nil {
		logger.Debug("dkim verification complete",
			zap.Bool("valid", res.Valid),
			zap.String("domain", res.Domain),
		)
	}
	return res, nil
}

func lookupTXTWithCache(ctx context.Context, domain string) ([]string, error) {
	selector := ""
	d := ""
	if parts := strings.SplitN(domain, "._domainkey.", 2); len(parts) == 2 {
		selector = parts[0]
		d = parts[1]
	}

	cacheKey := ""
	if selector != "" && d != "" {
		cacheKey = fmt.Sprintf("dkim:key:%s:%s", selector, d)
		if rdb != nil {
			if val, err := rdb.Get(ctx, cacheKey).Result(); err == nil {
				return []string{val}, nil
			}
		}
	}

	txts, ttl, err := txtLookup(ctx, domain)
	if err != nil {
		return nil, err
	}

	if cacheKey != "" && rdb != nil && len(txts) > 0 {
		dur := cfg.Auth.DKIM.CacheTTL
		if ttl > 0 {
			dur = time.Duration(ttl) * time.Second
		}
		if dur == 0 {
			dur = time.Hour
		}
		_ = rdb.Set(ctx, cacheKey, txts[0], dur).Err()
	}
	return txts, nil
}
