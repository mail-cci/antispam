package milt

import (
	"net"
	"net/textproto"
	"strings"
	"testing"

	"github.com/emersion/go-milter"
	"go.uber.org/zap"
)

func TestEmailParsing(t *testing.T) {
	logger := zap.NewNop()
	Init(logger)
	e := MailProcessor()
	defer e.Close()

	// provide client information so SPF checks do not short-circuit
	_, _ = e.Connect("localhost", "tcp4", 25, net.ParseIP("127.0.0.1"), nil)
	_, _ = e.Helo("localhost", nil)
	_, _ = e.MailFrom("a@b", nil)

	hdr := textproto.MIMEHeader{}
	hdr.Add("From", "a@b")
	hdr.Add("To", "c@d")
	hdr.Add("Subject", "Test")
	hdr.Add("Content-Type", "multipart/mixed; boundary=\"b\"")

	if _, err := e.Headers(hdr, nil); err != nil {
		t.Fatalf("Headers returned error: %v", err)
	}

	body := strings.Join([]string{
		"--b",
		"Content-Type: text/plain",
		"",
		"Hello",
		"--b",
		"Content-Type: text/plain",
		"Content-Disposition: attachment; filename=\"file.txt\"",
		"",
		"content",
		"--b--",
		"",
	}, "\r\n")

	if _, err := e.BodyChunk([]byte(body), nil); err != nil {
		t.Fatalf("BodyChunk error: %v", err)
	}

	if resp, err := e.Body(nil); err != nil || resp != milter.RespAccept {
		t.Fatalf("Body returned resp=%v err=%v", resp, err)
	}

	if e.rawBody.String() != "Hello" {
		t.Errorf("unexpected body: %q", e.rawBody.String())
	}
	if len(e.attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(e.attachments))
	}
	if e.attachments[0].Filename != "file.txt" {
		t.Errorf("unexpected attachment name: %s", e.attachments[0].Filename)
	}
}

func TestBodyChunkShort(t *testing.T) {
	logger := zap.NewNop()
	Init(logger)
	e := MailProcessor()
	defer e.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("BodyChunk panicked: %v", r)
		}
	}()

	if resp, err := e.BodyChunk([]byte("short"), nil); err != nil || resp != milter.RespContinue {
		t.Fatalf("BodyChunk returned resp=%v err=%v", resp, err)
	}
}
