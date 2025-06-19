package spf

import (
	"context"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"net"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

const maxRecursiveDepth = 10

// Internal data structures translated from spf.h

type spfAddr struct {
	IP4       net.IP
	IP6       net.IP
	Mask4     int
	Mask6     int
	Flags     uint32
	Mech      spfMech
	SPFString string
}

type spfResolved struct {
	Domain    string
	TopRecord string
	TTL       uint32
	Flags     int
	Timestamp time.Time
	Addrs     []spfAddr
}

type spfMech int

const (
	mechFail spfMech = iota
	mechSoftFail
	mechPass
	mechNeutral
)

func qualifierResult(q byte) string {
	switch q {
	case '+':
		return "pass"
	case '-':
		return "fail"
	case '~':
		return "softfail"
	case '?':
		return "neutral"
	default:
		return "neutral"
	}
}

func ipNetContains(ip net.IP, network net.IP, mask int) bool {
	if network == nil {
		return false
	}
	if ip.To4() != nil {
		n := &net.IPNet{IP: network.To4(), Mask: net.CIDRMask(mask, 32)}
		return n.Contains(ip)
	}
	n := &net.IPNet{IP: network, Mask: net.CIDRMask(mask, 128)}
	return n.Contains(ip)
}

// lookupTXT resolves TXT records for domain using miekg/dns to respect context
// deadlines. It returns the records and the lowest TTL observed.
func lookupTXT(ctx context.Context, domain string) ([]string, uint32, error) {
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

func parseMechanism(tok string) (q byte, name, val string) {
	if tok == "" {
		return '+', "", ""
	}
	switch tok[0] {
	case '+', '-', '~', '?':
		q = tok[0]
		tok = tok[1:]
	default:
		q = '+'
	}
	if i := strings.IndexAny(tok, ":="); i != -1 {
		name = tok[:i]
		val = tok[i+1:]
	} else {
		name = tok
	}
	return
}

func checkSPF(logger *zap.Logger, ctx context.Context, ip net.IP, domain, sender string, depth int) (string, uint32, error) {

	if depth > maxRecursiveDepth {
		logger.Error("límite de recursión SPF alcanzado",
			zap.Int("depth", depth),
			zap.String("domain", domain),
		)
		return "permerror", 0, errors.New("spf recursion limit reached")
	}

	// Buscar registros TXT
	logger.Debug("buscando registros TXT", zap.String("domain", domain))
	txts, ttl, err := lookupTXT(ctx, domain)
	if err != nil {
		logger.Error("error al buscar TXT records",
			zap.String("domain", domain),
			zap.Error(err),
		)
		return "temperror", 0, err
	}

	// Buscar registro SPF
	var record string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			record = t
			break
		}
	}

	if record == "" {
		return "none", 0, nil
	}

	parts := strings.Fields(record)

	for _, tok := range parts[1:] { // skip v=spf1
		q, mech, val := parseMechanism(tok)

		switch mech {
		case "ip4":
			ipstr, maskstr := val, ""
			if idx := strings.Index(val, "/"); idx != -1 {
				ipstr = val[:idx]
				maskstr = val[idx+1:]
			}
			network := net.ParseIP(ipstr)
			mask := 32
			if maskstr != "" {
				if m, err := strconv.Atoi(maskstr); err == nil {
					mask = m
				}
			}

			if ip.To4() != nil && ipNetContains(ip, network, mask) {
				logger.Info("ip4 match encontrado",
					zap.String("ip", ip.String()),
					zap.String("network", fmt.Sprintf("%s/%d", ipstr, mask)),
					zap.String("result", qualifierResult(q)),
				)
				return qualifierResult(q), ttl, nil
			}

		case "ip6":
			ipstr, maskstr := val, ""
			if idx := strings.Index(val, "/"); idx != -1 {
				ipstr = val[:idx]
				maskstr = val[idx+1:]
			}
			network := net.ParseIP(ipstr)
			mask := 128
			if maskstr != "" {
				if m, err := strconv.Atoi(maskstr); err == nil {
					mask = m
				}
			}

			if ip.To4() == nil && ipNetContains(ip, network, mask) {
				return qualifierResult(q), ttl, nil
			}

		case "a":
			host := val
			if host == "" {
				host = domain
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				logger.Warn("error resolviendo A records",
					zap.String("host", host),
					zap.Error(err),
				)
			} else {
				for _, h := range ips {
					if h.Equal(ip) {
						return qualifierResult(q), ttl, nil
					}
				}
			}

		case "mx":
			host := val
			if host == "" {
				host = domain
			}

			mxs, err := net.DefaultResolver.LookupMX(ctx, host)
			if err != nil {
				logger.Warn("error resolviendo MX records",
					zap.String("host", host),
					zap.Error(err),
				)
			} else {
				for _, mx := range mxs {
					ips, err := net.DefaultResolver.LookupIP(ctx, "ip", mx.Host)
					if err != nil {
						logger.Warn("error resolviendo IPs de MX",
							zap.String("mx_host", mx.Host),
							zap.Error(err),
						)
						continue
					}

					for _, h := range ips {
						if h.Equal(ip) {
							return qualifierResult(q), ttl, nil
						}
					}
				}
			}

		case "include":
			inc := val
			r, _, err := checkSPF(logger, ctx, ip, inc, sender, depth+1)
			if err == nil && r == "pass" {
				return qualifierResult(q), ttl, nil
			}

		case "redirect":
			red := val
			result, _, err := checkSPF(logger, ctx, ip, red, sender, depth+1)
			return result, ttl, err

		case "all":
			return qualifierResult(q), ttl, nil

		default:
			logger.Warn("mecanismo SPF no soportado",
				zap.String("mechanism", mech),
				zap.String("token", tok),
			)
		}
	}
	return "neutral", 0, nil
}
