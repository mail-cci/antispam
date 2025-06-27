package milt

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	_ "github.com/emersion/go-message/charset"

	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/internal/dkim"
	"github.com/mail-cci/antispam/internal/dmarc"
	"github.com/mail-cci/antispam/internal/scoring"
	"github.com/mail-cci/antispam/internal/spf"
	"github.com/mail-cci/antispam/internal/types"
	"github.com/mail-cci/antispam/pkg/helpers"
	"go.uber.org/zap"
	"net"
	"net/textproto"
	"strings"
	"sync"
)

var moduleLogger *zap.Logger

func Init(l *zap.Logger) {
	moduleLogger = l
}

type Email struct {
	logger      *zap.Logger
	id          string
	sender      string
	from        string
	client      map[string]string
	helo        string
	status      string
	headers     textproto.MIMEHeader
	rawBody     bytes.Buffer
	attachments []Attachment
	clientIP    net.IP
	heloHost    string
	recipients  []string
	rawEmail    bytes.Buffer
}

// Attachment stores metadata and content for an email attachment.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Reset clears all fields so the Email instance can be reused.
func (e *Email) Reset() {
	e.logger = nil
	e.id = ""
	e.sender = ""
	e.from = ""
	e.client = nil
	e.helo = ""
	e.status = ""
	e.headers = nil
	e.rawBody.Reset()
	e.attachments = nil
	e.clientIP = nil
	e.heloHost = ""
	e.recipients = nil
	e.rawEmail.Reset()
}

var emailPool = sync.Pool{
	New: func() interface{} { return new(Email) },
}

func MailProcessor() *Email {
	e := emailPool.Get().(*Email)
	e.Reset()
	e.logger = moduleLogger
	e.client = make(map[string]string)
	e.headers = make(textproto.MIMEHeader)
	return e
}

func (e *Email) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	e.id = helpers.GenerateCorrelationID()
	e.logger = moduleLogger.With(zap.String("correlation_id", e.id))
	e.client["host"] = host
	e.client["family"] = family
	e.client["port"] = fmt.Sprintf("%d", port)
	e.client["addr"] = addr.String()
	e.clientIP = addr
	return milter.RespContinue, nil
}

func (e *Email) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	e.heloHost = name
	return milter.RespContinue, nil
}

func (e *Email) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	e.from = from
	return milter.RespContinue, nil
}

func (e *Email) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	e.recipients = append(e.recipients, rcptTo)
	return milter.RespContinue, nil
}

func (e *Email) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	e.headers.Add(name, value)
	return milter.RespContinue, nil
}

func (e *Email) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	e.headers = h
	return milter.RespContinue, nil
}

func (e *Email) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	preview := chunk
	if len(preview) > 10 {
		preview = preview[:10]
	}
	e.rawBody.Write(chunk)
	e.rawEmail.Write(chunk)
	return milter.RespContinue, nil
}

func (e *Email) Body(m *milter.Modifier) (milter.Response, error) {
	start := time.Now()

	// Si la IP o el nombre del cliente no fueron provistos durante el
	// evento Connect, intentar recuperarlos de las macros enviadas por el
	// MTA. Algunos MTAs solo envíen estos datos mediante macros y no en
	// el comando inicial de conexión.
	if m != nil {
		if e.clientIP == nil {
			if ipStr := m.Macros["client_addr"]; ipStr != "" {
				if ip := net.ParseIP(ipStr); ip != nil {
					e.clientIP = ip
					e.client["addr"] = ipStr
				}
			}
		}
		if e.client["host"] == "" {
			if host := m.Macros["client_name"]; host != "" {
				e.client["host"] = host
			}
		}
	}

	e.rawEmail.Reset()
	for k, vv := range e.headers {
		for _, v := range vv {
			_, err := fmt.Fprintf(&e.rawEmail, "%s: %s\r\n", k, v)
			if err != nil {
				return nil, err
			}
		}
	}
	e.rawEmail.WriteString("\r\n")
	e.rawEmail.Write(e.rawBody.Bytes())

	mr, err := mail.CreateReader(bytes.NewReader(e.rawEmail.Bytes()))
	if err != nil {
		e.logger.Error("Failed to create MIME reader", zap.Error(err))
		return milter.RespContinue, nil
	}

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			e.logger.Error("Error reading MIME part", zap.Error(err))
			return milter.RespContinue, nil
		}

		switch h := p.Header.(type) {
		case *mail.InlineHeader:
			data, _ := io.ReadAll(p.Body)
			e.rawBody.Reset()
			e.rawBody.Write(data)
		case *mail.AttachmentHeader:
			filename, _ := h.Filename()
			ctype, _, err := h.ContentType()
			if err != nil {
				ctype = ""
			}
			data, _ := io.ReadAll(p.Body)
			e.attachments = append(e.attachments, Attachment{
				Filename:    filename,
				ContentType: ctype,
				Data:        data,
			})
		}
	}

	ctx := context.Background()

	// Extract From header domain for DMARC preparation
	var fromHeaderDomain string
	fromHeader := e.headers.Get("From")
	if fromHeader != "" {
		fromHeaderDomain = extractFromHeaderDomain(fromHeader)
		e.logger.Debug("Extracted From header domain",
			zap.String("from_header", fromHeader),
			zap.String("from_domain", fromHeaderDomain))
	}

	// Manejo especial para bounces (from vacío o <>)
	var spfDomain string
	var isBounceMail bool

	if e.from == "" || e.from == "<>" {
		// Para bounces, usar el dominio del HELO
		isBounceMail = true
		spfDomain = e.heloHost
		e.logger.Info("Bounce detected, using HELO domain for SPF validation",
			zap.String("helo_host", e.heloHost),
			zap.String("from", e.from),
		)
	} else {
		// Para emails normales, extraer dominio del FROM
		spfDomain = helpers.ExtractDomain(e.from)
	}

	if spfDomain == "" {
		if isBounceMail {
			e.logger.Error("Invalid HELO domain for bounce message",
				zap.String("helo_host", e.heloHost),
				zap.String("from", e.from),
				zap.String("client_host", e.client["host"]),
				zap.String("client_addr", e.client["addr"]))
		} else {
			e.logger.Error("Invalid domain in 'From' address",
				zap.String("from", e.from),
				zap.String("client_host", e.client["host"]),
				zap.String("client_addr", e.client["addr"]))
		}
		return milter.RespContinue, nil
	}

	if e.clientIP == nil {
		e.logger.Error("Client IP is nil", zap.String("from", e.from))
		e.logger.Error("Client IP details", zap.String("host", e.client["host"]), zap.String("addr", e.client["addr"]))
	}

	var wg sync.WaitGroup
	wg.Add(2) // SPF and DKIM (DMARC will run after these complete)

	var spfRes *types.SPFResult
	var dkimRes *types.DKIMResult
	var dmarcRes *types.DMARCResult

	// Start SPF check in goroutine
	go func() {
		defer wg.Done()

		// Para bounces, usar el HELO host en lugar del sender para SPF
		senderForSPF := e.from
		if isBounceMail {
			senderForSPF = "" // Para bounces, el sender efectivo es vacío
		}

		res, err := spf.Verify(ctx, e.clientIP, spfDomain, senderForSPF)
		if err != nil {
			e.logger.Error("Error verifying SPF",
				zap.Error(err),
				zap.String("domain", spfDomain),
				zap.String("from", e.from),
				zap.Bool("is_bounce", isBounceMail))
			return
		}
		spfRes = res
	}()

	// Start DKIM check in goroutine
	go func() {
		defer wg.Done()
		
               res, err := dkim.VerifyForDMARC(e.rawEmail.Bytes(), fromHeaderDomain, e.id)
		if err != nil {
			e.logger.Error("Error verifying DKIM", zap.Error(err))
			return
		}
		dkimRes = res
	}()

	// Wait for both checks with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Apply timeout for both SPF and DKIM checks
	timeout := 15 * time.Second
	select {
	case <-done:
		// Both checks completed
	case <-time.After(timeout):
		e.logger.Warn("Authentication checks timed out",
			zap.Duration("timeout", timeout),
			zap.Bool("spf_completed", spfRes != nil),
			zap.Bool("dkim_completed", dkimRes != nil))
		
		// Provide default results for incomplete checks
		if spfRes == nil {
			spfRes = &types.SPFResult{Result: "timeout", Score: 2}
		}
		if dkimRes == nil {
			dkimRes = &types.DKIMResult{Valid: false, Score: 3}
		}
	}

	// DMARC verification (runs after SPF and DKIM complete)
	if fromHeaderDomain != "" && !isBounceMail {
		// Create DMARC verifier
		dmarcVerifier := dmarc.NewVerifier(e.logger, nil, &dmarc.Config{
			Enabled:  true,
			Timeout:  5 * time.Second,
			CacheTTL: 4 * time.Hour,
		})
		
		// Perform DMARC verification
		dmarcCtx, dmarcCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dmarcCancel()
		
		dmarcResult, err := dmarcVerifier.Verify(dmarcCtx, fromHeaderDomain, spfRes, dkimRes)
		if err != nil {
			e.logger.Error("Error verifying DMARC",
				zap.Error(err),
				zap.String("from_domain", fromHeaderDomain))
			// Continue with default DMARC result
			dmarcRes = &types.DMARCResult{
				Valid:       false,
				Disposition: "none",
				Score:       0.5,
				Error:       err.Error(),
			}
		} else {
			dmarcRes = dmarcResult
		}
	} else {
		// No DMARC for bounces or emails without From domain
		dmarcRes = &types.DMARCResult{
			Valid:       false,
			Disposition: "none",
			Score:       0.0,
			Error:       "no from domain or bounce email",
		}
	}

	var total float64
	if spfRes != nil {
		total += spfRes.Score
	}
	if dkimRes != nil {
		total += dkimRes.Score
	}
	if dmarcRes != nil {
		total += dmarcRes.Score
	}

	decision := scoring.Decide(total)

	if m != nil {
		err := m.AddHeader("X-Spam-Score", fmt.Sprintf("%.2f", total))
		if err != nil {
			return nil, err
		}
		
		// Add SPF headers
		if spfRes != nil {
			err := m.AddHeader("X-SPF-Result", spfRes.Result)
			if err != nil {
				return nil, err
			}
			headerValue := fmt.Sprintf("%s (domain of %s designates %s as permitted sender) client-ip=%s; envelope-from=%s", spfRes.Result, spfRes.Domain, e.clientIP.String(), e.clientIP.String(), e.from)
			err = m.AddHeader("Received-SPF", headerValue)
			if err != nil {
				return nil, err
			}
		} else {
			err := m.AddHeader("X-SPF-Result", "")
			if err != nil {
				return nil, err
			}
		}
		
		// Add enhanced DKIM headers
		if dkimRes != nil {
			// Main DKIM result header
			dkimStatus := "fail"
			if dkimRes.Valid {
				dkimStatus = "pass"
			}
			err := m.AddHeader("X-DKIM-Result", dkimStatus)
			if err != nil {
				return nil, err
			}
			
			// Enhanced DKIM information headers
			err = m.AddHeader("X-DKIM-Signatures", fmt.Sprintf("%d", dkimRes.TotalSignatures))
			if err != nil {
				return nil, err
			}
			
			err = m.AddHeader("X-DKIM-Valid", fmt.Sprintf("%d", dkimRes.ValidSignatures))
			if err != nil {
				return nil, err
			}
			
			if dkimRes.Domain != "" {
				err = m.AddHeader("X-DKIM-Domain", dkimRes.Domain)
				if err != nil {
					return nil, err
				}
			}
			
			// Add edge case information if present
			if dkimRes.EdgeCaseInfo != nil && len(dkimRes.EdgeCaseInfo.Anomalies) > 0 {
				err = m.AddHeader("X-DKIM-Anomalies", fmt.Sprintf("%v", dkimRes.EdgeCaseInfo.Anomalies))
				if err != nil {
					return nil, err
				}
				
				err = m.AddHeader("X-DKIM-Threat-Level", string(dkimRes.EdgeCaseInfo.ThreatLevel))
				if err != nil {
					return nil, err
				}
			}
		} else {
			err := m.AddHeader("X-DKIM-Result", "none")
			if err != nil {
				return nil, err
			}
		}
		
		// Add DMARC headers
		if dmarcRes != nil {
			dmarcStatus := "fail"
			if dmarcRes.Valid {
				dmarcStatus = "pass"
			}
			err := m.AddHeader("X-DMARC-Result", dmarcStatus)
			if err != nil {
				return nil, err
			}
			
			err = m.AddHeader("X-DMARC-Disposition", dmarcRes.Disposition)
			if err != nil {
				return nil, err
			}
			
			if dmarcRes.Policy != nil {
				err = m.AddHeader("X-DMARC-Policy", dmarcRes.Policy.Policy)
				if err != nil {
					return nil, err
				}
			}
			
			if dmarcRes.Alignment != nil {
				err = m.AddHeader("X-DMARC-SPF-Aligned", fmt.Sprintf("%t", dmarcRes.Alignment.SPFAligned))
				if err != nil {
					return nil, err
				}
				
				err = m.AddHeader("X-DMARC-DKIM-Aligned", fmt.Sprintf("%t", dmarcRes.Alignment.DKIMAligned))
				if err != nil {
					return nil, err
				}
			}
		}
		
		// Add From domain header for DMARC preparation
		if fromHeaderDomain != "" {
			err := m.AddHeader("X-From-Domain", fromHeaderDomain)
			if err != nil {
				return nil, err
			}
		}
		
		err = m.AddHeader("X-Spam-Status", decision)
		if err != nil {
			return nil, err
		}
		if decision == "quarantine" {
			err := m.AddHeader("X-Spam-Flag", "YES")
			if err != nil {
				return nil, err
			}
		}
	}

	spfResult := ""
	if spfRes != nil {
		spfResult = spfRes.Result
	}

	e.logger.Info("[cci-spam-inbound-prefilter] - Processed email",
		zap.String("message_id", e.headers.Get("Message-ID")),
		zap.String("from", e.from),
		zap.String("from_header_domain", fromHeaderDomain),
		zap.Strings("recipients", e.recipients),
		zap.String("ip", e.clientIP.String()),
		zap.Any("spf", spfRes),
		zap.Any("dkim", dkimRes),
		zap.Any("dmarc", dmarcRes),
		zap.Float64("total", total),
		zap.String("decision", decision),
		zap.Duration("duration", time.Since(start)),
		zap.String("spf_result", spfResult),
		zap.Bool("is_bounce", isBounceMail),
		zap.String("spf_domain", spfDomain),
	)

	if decision == "reject" {
		return milter.RespContinue, nil
	}
	return milter.RespAccept, nil
}

func (e *Email) Abort(m *milter.Modifier) error {
	return nil
}

// Close is called when the milter session ends.
func (e *Email) Close() error {
	e.Reset()
	emailPool.Put(e)
	return nil
}

// extractFromHeaderDomain extracts the domain from a From header field
func extractFromHeaderDomain(fromHeader string) string {
	if fromHeader == "" {
		return ""
	}

	// Handle cases with display names and angle brackets
	// Examples:
	// "John Doe <john@example.com>" -> "example.com"
	// "john@example.com" -> "example.com"
	// "<john@example.com>" -> "example.com"
	
	// Remove display name and quotes
	fromHeader = strings.TrimSpace(fromHeader)
	
	// Extract email from angle brackets if present
	if strings.Contains(fromHeader, "<") && strings.Contains(fromHeader, ">") {
		start := strings.Index(fromHeader, "<")
		end := strings.Index(fromHeader, ">")
		if start < end && start >= 0 && end > start {
			fromHeader = fromHeader[start+1 : end]
		}
	}
	
	// Remove any remaining quotes
	fromHeader = strings.Trim(fromHeader, "\"'")
	fromHeader = strings.TrimSpace(fromHeader)
	
	// Find the @ symbol
	atIndex := strings.LastIndex(fromHeader, "@")
	if atIndex == -1 || atIndex == len(fromHeader)-1 {
		return ""
	}
	
	// Extract domain part
	domain := fromHeader[atIndex+1:]
	domain = strings.ToLower(strings.TrimSpace(domain))
	
	// Remove any trailing characters that shouldn't be in a domain
	domain = strings.Trim(domain, " \t\r\n>)")
	
	return domain
}
