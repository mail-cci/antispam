package milt

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"sync"

	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/pkg/helpers"
	"go.uber.org/zap"
)

type Store interface {
	SaveEmail(*Email) (int64, error)
	SaveSpamScore(int64, string, float64, float64, bool) error
	QuarantineEmail(int64, string) error
}

type Email struct {
	logger      *zap.Logger
	store       Store
	id          string
	sender      string
	from        string
	client      map[string]string
	helo        string
	status      string
	headers     textproto.MIMEHeader
	rawBody     bytes.Buffer
	attachments []Attachment
}

// Attachment stores metadata and content for an email attachment.
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// ID returns the correlation ID for the email.
func (e *Email) ID() string { return e.id }

// From returns the envelope sender address.
func (e *Email) From() string { return e.from }

// ClientAddr returns the connecting client's IP address.
func (e *Email) ClientAddr() string { return e.client["addr"] }

// Helo returns the HELO/EHLO name used by the client.
func (e *Email) Helo() string { return e.helo }

// Headers returns the collected headers.
func (e *Email) Headers() textproto.MIMEHeader { return e.headers }

// Body returns the message body as a string.
func (e *Email) Body() string { return e.rawBody.String() }

// Attachments returns the parsed attachments.
func (e *Email) Attachments() []Attachment { return e.attachments }

// Reset clears all fields so the Email instance can be reused.
func (e *Email) Reset() {
	e.logger = nil
	e.store = nil
	e.id = ""
	e.sender = ""
	e.from = ""
	e.client = nil
	e.helo = ""
	e.status = ""
	e.headers = nil
	e.rawBody.Reset()
	e.attachments = nil
}

var emailPool = sync.Pool{
	New: func() interface{} { return new(Email) },
}

func MailProcessor(logger *zap.Logger, store Store) *Email {
	e := emailPool.Get().(*Email)
	e.Reset()
	e.logger = logger
	e.store = store
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
	e.helo = name
	e.logger.Debug("[cci-spam-inbound-prefilter] - Helo: ",
		zap.String("name", name),
		zap.String("correlation_id", e.id),
		zap.String("type", "helo/ehlo"))
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
	return milter.RespContinue, nil
}

func (e *Email) Body(m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Body: ",
		zap.String("correlation_id", e.id),
		zap.String("type", "body"))

	var raw bytes.Buffer
	// Reconstruct full email from headers and collected body
	for k, vv := range e.headers {
		for _, v := range vv {
			fmt.Fprintf(&raw, "%s: %s\r\n", k, v)
		}
	}
	raw.WriteString("\r\n")
	raw.Write(e.rawBody.Bytes())

	mr, err := mail.CreateReader(&raw)
	if err != nil {
		e.logger.Error("failed to parse email", zap.Error(err))
		return milter.RespTempFail, nil
	}

	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			e.logger.Error("error reading MIME part", zap.Error(err))
			return milter.RespTempFail, nil
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

	if e.store != nil {
		id, err := e.store.SaveEmail(e)
		if err != nil {
			e.logger.Error("failed to store email", zap.Error(err))
			return milter.RespTempFail, nil
		}
		// placeholder spam score
		if err := e.store.SaveSpamScore(id, "none", 0, 0, false); err != nil {
			e.logger.Error("failed to store spam score", zap.Error(err))
		}
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
