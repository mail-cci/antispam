package milt

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/internal/storage"
	"github.com/mail-cci/antispam/pkg/helpers"
	"go.uber.org/zap"
	"net"
	"net/textproto"
	"sync"
)

type Email struct {
	logger      *zap.Logger
	store       *storage.Storage
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

func MailProcessor(logger *zap.Logger, store *storage.Storage) *Email {
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
		if err := e.store.SaveEmail(context.Background(), e); err != nil {
			e.logger.Error("failed to save email", zap.Error(err))
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

// Accessors used by storage layer
func (e *Email) ID() string                    { return e.id }
func (e *Email) From() string                  { return e.from }
func (e *Email) Helo() string                  { return e.helo }
func (e *Email) Client() map[string]string     { return e.client }
func (e *Email) Headers() textproto.MIMEHeader { return e.headers }
func (e *Email) Body() string                  { return e.rawBody.String() }
func (e *Email) Attachments() []Attachment     { return e.attachments }
