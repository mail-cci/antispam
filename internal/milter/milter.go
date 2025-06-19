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
	e.logger.Debug("[cci-spam-inbound-prefilter] - Connect: ",
		zap.String("host", host),
		zap.String("family", family),
		zap.Uint16("port", port),
		zap.String("addr", addr.String()),
		zap.String("correlation_id", e.id),
		zap.String("type", "connect"))
	return milter.RespContinue, nil
}

func (e *Email) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Helo: ",
		zap.String("name", name),
		zap.String("correlation_id", e.id),
		zap.String("type", "helo/ehlo"))
	e.heloHost = name
	return milter.RespContinue, nil
}

func (e *Email) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - From: ",
		zap.String("from", from),
		zap.String("correlation_id", e.id),
		zap.String("type", "mail_from"))
	e.from = from
	return milter.RespContinue, nil
}

func (e *Email) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - RcptTo:",
		zap.String("rcpt_to", rcptTo),
		zap.String("correlation_id", e.id),
		zap.String("type", "rcpt_to"))
	e.recipients = append(e.recipients, rcptTo)
	return milter.RespContinue, nil
}

func (e *Email) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Header: ",
		zap.String("name", name),
		zap.String("value", value),
		zap.String("correlation_id", e.id),
		zap.String("type", "header"))
	e.headers.Add(name, value)
	return milter.RespContinue, nil
}

func (e *Email) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Headers: ",
		zap.Any("headers", h),
		zap.String("correlation_id", e.id),
		zap.String("type", "headers"))
	e.headers = h
	return milter.RespContinue, nil
}

func (e *Email) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	preview := chunk
	if len(preview) > 10 {
		preview = preview[:10]
	}
	e.logger.Debug("[cci-spam-inbound-prefilter] - BodyChunk: ",
		zap.String("chunk", string(preview)),
		zap.String("correlation_id", e.id),
		zap.String("type", "body_chunk"))
	e.rawBody.Write(chunk)
	e.rawEmail.Write(chunk)
	return milter.RespContinue, nil
}

func (e *Email) Body(m *milter.Modifier) (milter.Response, error) {
	start := time.Now()
	e.logger.Debug("[cci-spam-inbound-prefilter] - Body: ",
		zap.String("correlation_id", e.id),
		zap.String("type", "body"))

	e.rawEmail.Reset()
	for k, vv := range e.headers {
		for _, v := range vv {
			fmt.Fprintf(&e.rawEmail, "%s: %s\r\n", k, v)
		}
	}
	e.rawEmail.WriteString("\r\n")
	e.rawEmail.Write(e.rawBody.Bytes())

	mr, err := mail.CreateReader(bytes.NewReader(e.rawEmail.Bytes()))
	if err != nil {
		e.logger.Error("failed to parse email", zap.Error(err))
		return milter.RespContinue, nil
	}

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			e.logger.Error("error reading MIME part", zap.Error(err))
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
	domain := helpers.ExtractDomain(e.from)

	if domain == "" {
		e.logger.Error("invalid domain extracted from sender", zap.String("from", e.from))
		return milter.RespContinue, nil
	}

	if e.clientIP == nil {
		e.logger.Error("client IP is nil")
		return milter.RespContinue, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var spfRes *types.SPFResult

	go func() {
		defer wg.Done()
		res, err := spf.Verify(ctx, e.clientIP, domain, e.from)
		if err != nil {
			e.logger.Error("spf verification failed", zap.Error(err))
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
		m.AddHeader("X-Spam-Score", fmt.Sprintf("%.2f", total))
		if spfRes != nil {
			m.AddHeader("X-SPF-Result", spfRes.Result)
		} else {
			m.AddHeader("X-SPF-Result", "")
		}
		m.AddHeader("X-Spam-Status", decision)
		if decision == "quarantine" {
			m.AddHeader("X-Spam-Flag", "YES")
		}
	}

	e.logger.Info("email processed",
		zap.String("message_id", e.headers.Get("Message-ID")),
		zap.String("from", e.from),
		zap.Strings("recipients", e.recipients),
		zap.String("ip", e.clientIP.String()),
		zap.Any("spf", spfRes),
		zap.Float64("total", total),
		zap.String("decision", decision),
		zap.Duration("duration", time.Since(start)),
	)

	if decision == "reject" {
		return milter.RespContinue, nil
	}
	return milter.RespAccept, nil
}

func (e *Email) Abort(m *milter.Modifier) error {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Abort: ",
		zap.String("correlation_id", e.id),
		zap.String("type", "abort"))
	return nil
}

// Close is called when the milter session ends.
func (e *Email) Close() error {
	if e.logger != nil {
		e.logger.Debug("[cci-spam-inbound-prefilter] - Close:",
			zap.String("correlation_id", e.id),
			zap.String("type", "close"))
	}
	e.Reset()
	emailPool.Put(e)
	return nil
}
