package milt

import (
	"bytes"
	"context"
	"net"
	"net/textproto"
	"testing"
	"time"

	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/spf"
	"go.uber.org/zap"
)

// helper to set private writePacket field using reflection
// and record headers added via AddHeader

import (
	"reflect"
	"unsafe"
)

type headerRecorder struct {
	m       *milter.Modifier
	headers textproto.MIMEHeader
}

func newHeaderRecorder() *headerRecorder {
	hr := &headerRecorder{
		m:       &milter.Modifier{},
		headers: make(textproto.MIMEHeader),
	}
	hr.m.Headers = hr.headers
	hr.m.Macros = make(map[string]string)
	fn := func(msg *milter.Message) error {
		if msg.Code == byte(milter.ActAddHeader) {
			parts := bytes.SplitN(msg.Data, []byte{0}, 3)
			if len(parts) >= 2 {
				name := string(parts[0])
				value := string(parts[1])
				hr.headers.Add(name, value)
			}
		}
		return nil
	}
	v := reflect.ValueOf(hr.m).Elem().FieldByName("writePacket")
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(fn))
	return hr
}

func TestReceivedSPFHeaderAdded(t *testing.T) {
	logger := zap.NewNop()
	cfg := &config.Config{
		Auth: config.AuthConfig{SPF: config.SPFConfig{Timeout: time.Second}},
	}
	oldCfg := spfCfg
	spf.Init(cfg, zap.NewNop())
	// stub TXT lookups to return pass record
	setTxtLookup(func(ctx context.Context, domain string) ([]string, uint32, error) {
		return []string{"v=spf1 +all"}, 600, nil
	})
	defer func() {
		setTxtLookup(nil)
		spfCfg = oldCfg
	}()

	Init(logger)
	e := MailProcessor()
	defer e.Close()

	_, _ = e.Connect("localhost", "tcp4", 25, net.ParseIP("127.0.0.1"), nil)
	_, _ = e.Helo("localhost", nil)
	_, _ = e.MailFrom("user@test.local", nil)

	hdr := textproto.MIMEHeader{}
	hdr.Add("From", "user@test.local")
	hdr.Add("To", "dest@example.com")
	hdr.Add("Subject", "Test")

	if _, err := e.Headers(hdr, nil); err != nil {
		t.Fatalf("Headers returned error: %v", err)
	}

	if _, err := e.BodyChunk([]byte("body"), nil); err != nil {
		t.Fatalf("BodyChunk error: %v", err)
	}

	rec := newHeaderRecorder()
	if resp, err := e.Body(rec.m); err != nil || resp != milter.RespAccept {
		t.Fatalf("Body returned resp=%v err=%v", resp, err)
	}

	if rec.headers.Get("Received-SPF") == "" {
		t.Error("Received-SPF header missing")
	}
}
