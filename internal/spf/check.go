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

func checkSPF(logger *zap.Logger, ctx context.Context, ip net.IP, domain, sender string, depth int) (string, error) {
	// Log inicio de validación
	logger.Debug("iniciando validación SPF",
		zap.String("domain", domain),
		zap.String("ip", ip.String()),
		zap.String("sender", sender),
		zap.Int("depth", depth),
	)

	if depth > maxRecursiveDepth {
		logger.Error("límite de recursión SPF alcanzado",
			zap.Int("depth", depth),
			zap.String("domain", domain),
		)
		return "permerror", errors.New("spf recursion limit reached")
	}

	// Buscar registros TXT
	logger.Debug("buscando registros TXT", zap.String("domain", domain))
	txts, ttl, err := lookupTXT(ctx, domain)
	if err != nil {
		logger.Error("error al buscar TXT records",
			zap.String("domain", domain),
			zap.Error(err),
		)
		return "temperror", err
	}

	logger.Debug("registros TXT encontrados",
		zap.String("domain", domain),
		zap.Strings("records", txts),
		zap.Uint32("ttl", ttl),
		zap.Int("count", len(txts)),
	)

	// Buscar registro SPF
	var record string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(t), "v=spf1") {
			record = t
			logger.Debug("registro SPF encontrado",
				zap.String("domain", domain),
				zap.String("record", record),
			)
			break
		}
	}

	if record == "" {
		logger.Debug("no se encontró registro SPF",
			zap.String("domain", domain),
		)
		return "none", nil
	}

	parts := strings.Fields(record)
	logger.Debug("procesando mecanismos SPF",
		zap.String("domain", domain),
		zap.Int("mechanisms_count", len(parts)-1),
	)

	for i, tok := range parts[1:] { // skip v=spf1
		q, mech, val := parseMechanism(tok)

		logger.Debug("procesando mecanismo",
			zap.Int("position", i),
			zap.String("token", tok),
			zap.String("mechanism", mech),
			zap.String("value", val),
			zap.String("qualifier", string(q)),
			zap.String("qualifier_result", qualifierResult(q)),
		)

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

			logger.Debug("evaluando mecanismo ip4",
				zap.String("network", ipstr),
				zap.Int("mask", mask),
				zap.String("checking_ip", ip.String()),
				zap.Bool("is_ipv4", ip.To4() != nil),
			)

			if ip.To4() != nil && ipNetContains(ip, network, mask) {
				logger.Info("ip4 match encontrado",
					zap.String("ip", ip.String()),
					zap.String("network", fmt.Sprintf("%s/%d", ipstr, mask)),
					zap.String("result", qualifierResult(q)),
				)
				return qualifierResult(q), nil
			}

			logger.Debug("ip4 no match",
				zap.String("ip", ip.String()),
				zap.String("network", fmt.Sprintf("%s/%d", ipstr, mask)),
			)

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

			logger.Debug("evaluando mecanismo ip6",
				zap.String("network", ipstr),
				zap.Int("mask", mask),
				zap.String("checking_ip", ip.String()),
				zap.Bool("is_ipv6", ip.To4() == nil),
			)

			if ip.To4() == nil && ipNetContains(ip, network, mask) {
				logger.Info("ip6 match encontrado",
					zap.String("ip", ip.String()),
					zap.String("network", fmt.Sprintf("%s/%d", ipstr, mask)),
					zap.String("result", qualifierResult(q)),
				)
				return qualifierResult(q), nil
			}

			logger.Debug("ip6 no match",
				zap.String("ip", ip.String()),
				zap.String("network", fmt.Sprintf("%s/%d", ipstr, mask)),
			)

		case "a":
			host := val
			if host == "" {
				host = domain
			}

			logger.Debug("evaluando mecanismo 'a'",
				zap.String("host", host),
				zap.String("checking_ip", ip.String()),
			)

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				logger.Warn("error resolviendo A records",
					zap.String("host", host),
					zap.Error(err),
				)
			} else {
				logger.Debug("A records encontrados",
					zap.String("host", host),
					zap.Int("count", len(ips)),
				)

				for _, h := range ips {
					logger.Debug("comparando con A record",
						zap.String("a_record_ip", h.String()),
						zap.String("checking_ip", ip.String()),
						zap.Bool("match", h.Equal(ip)),
					)

					if h.Equal(ip) {
						logger.Info("A record match encontrado",
							zap.String("host", host),
							zap.String("ip", ip.String()),
							zap.String("result", qualifierResult(q)),
						)
						return qualifierResult(q), nil
					}
				}
			}

		case "mx":
			host := val
			if host == "" {
				host = domain
			}

			logger.Debug("evaluando mecanismo 'mx'",
				zap.String("host", host),
				zap.String("checking_ip", ip.String()),
			)

			mxs, err := net.DefaultResolver.LookupMX(ctx, host)
			if err != nil {
				logger.Warn("error resolviendo MX records",
					zap.String("host", host),
					zap.Error(err),
				)
			} else {
				logger.Debug("MX records encontrados",
					zap.String("host", host),
					zap.Int("count", len(mxs)),
				)

				for _, mx := range mxs {
					logger.Debug("procesando MX record",
						zap.String("mx_host", mx.Host),
						zap.Uint16("priority", mx.Pref),
					)

					ips, err := net.DefaultResolver.LookupIP(ctx, "ip", mx.Host)
					if err != nil {
						logger.Warn("error resolviendo IPs de MX",
							zap.String("mx_host", mx.Host),
							zap.Error(err),
						)
						continue
					}

					for _, h := range ips {
						logger.Debug("comparando con MX IP",
							zap.String("mx_host", mx.Host),
							zap.String("mx_ip", h.String()),
							zap.String("checking_ip", ip.String()),
							zap.Bool("match", h.Equal(ip)),
						)

						if h.Equal(ip) {
							logger.Info("MX match encontrado",
								zap.String("host", host),
								zap.String("mx_host", mx.Host),
								zap.String("ip", ip.String()),
								zap.String("result", qualifierResult(q)),
							)
							return qualifierResult(q), nil
						}
					}
				}
			}

		case "include":
			inc := val
			logger.Debug("evaluando mecanismo 'include'",
				zap.String("include_domain", inc),
				zap.Int("current_depth", depth),
			)

			r, err := checkSPF(logger, ctx, ip, inc, sender, depth+1)

			logger.Debug("resultado de include",
				zap.String("include_domain", inc),
				zap.String("result", r),
				zap.Error(err),
			)

			if err == nil && r == "pass" {
				logger.Info("include match encontrado",
					zap.String("include_domain", inc),
					zap.String("result", qualifierResult(q)),
				)
				return qualifierResult(q), nil
			}

		case "redirect":
			red := val
			logger.Debug("procesando redirect",
				zap.String("redirect_domain", red),
				zap.Int("current_depth", depth),
			)

			result, err := checkSPF(logger, ctx, ip, red, sender, depth+1)

			logger.Debug("resultado de redirect",
				zap.String("redirect_domain", red),
				zap.String("result", result),
				zap.Error(err),
			)

			return result, err

		case "all":
			logger.Info("mecanismo 'all' alcanzado",
				zap.String("result", qualifierResult(q)),
			)
			return qualifierResult(q), nil

		default:
			logger.Warn("mecanismo SPF no soportado",
				zap.String("mechanism", mech),
				zap.String("token", tok),
			)
		}
	}

	logger.Debug("fin de mecanismos SPF sin match, retornando neutral",
		zap.String("domain", domain),
	)
	return "neutral", nil
}
