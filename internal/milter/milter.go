package milt

import (
	"fmt"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/pkg/helpers"
	"go.uber.org/zap"
	"net"
	"net/textproto"
	"sync"
)

type Email struct {
	logger *zap.Logger
	id     string
	sender string
	from   string
	client map[string]string
	helo   string
	status string
}

var emailPool = sync.Pool{
	New: func() interface{} { return new(Email) },
}

func MailProcessor(logger *zap.Logger) *Email {
	e := emailPool.Get().(*Email)
	e.logger = logger
	e.client = make(map[string]string)
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
	return milter.RespContinue, nil
}

func (e *Email) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Headers: ",
		zap.Any("headers", h),
		zap.String("correlation_id", e.id),
		zap.String("type", "headers"))
	return milter.RespContinue, nil
}

func (e *Email) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - BodyChunk: ",
		zap.String("chunk", string(chunk[:10])),
		zap.String("correlation_id", e.id),
		zap.String("type", "body_chunk"))
	return milter.RespContinue, nil
}

func (e *Email) Body(m *milter.Modifier) (milter.Response, error) {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Body: ",
		zap.String("correlation_id", e.id),
		zap.String("type", "body"))
	return milter.RespAccept, nil
}

func (e *Email) Abort(m *milter.Modifier) error {
	e.logger.Debug("[cci-spam-inbound-prefilter] - Abort: ",
		zap.String("correlation_id", e.id),
		zap.String("type", "abort"))
	return nil
}
