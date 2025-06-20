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
	"github.com/mail-cci/antispam/internal/scoring"
	"github.com/mail-cci/antispam/internal/spf"
	"github.com/mail-cci/antispam/internal/types"
	"github.com/mail-cci/antispam/pkg/helpers"
	"go.uber.org/zap"
	"net"
	"net/textproto"
	"sync"
)

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

func MailProcessor(logger *zap.Logger) *Email {
	e := emailPool.Get().(*Email)
	e.Reset()
	e.logger = logger
	e.client = make(map[string]string)
	e.headers = make(textproto.MIMEHeader)
	return e
}

func (e *Email) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	e.id = helpers.GenerateCorrelationID()
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
		return milter.RespContinue, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var spfRes *types.SPFResult

	go func() {
		defer wg.Done()

		// Para bounces, usar el HELO host en lugar del sender para SPF
		senderForSPF := e.from
		if isBounceMail {
			senderForSPF = "" // Para bounces, el sender efectivo es vacío
		}

		res, err := spf.Verify(e.logger, ctx, e.clientIP, spfDomain, senderForSPF)
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

	wg.Wait()

	var total float64
	if spfRes != nil {
		total += spfRes.Score
	}

	decision := scoring.Decide(total)

	if m != nil {
		err := m.AddHeader("X-Spam-Score", fmt.Sprintf("%.2f", total))
		if err != nil {
			return nil, err
		}
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
		zap.Strings("recipients", e.recipients),
		zap.String("ip", e.clientIP.String()),
		zap.Any("spf", spfRes),
		zap.Float64("total", total),
		zap.String("decision", decision),
		zap.Duration("duration", time.Since(start)),
		zap.String("correlation_id", e.id),
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
