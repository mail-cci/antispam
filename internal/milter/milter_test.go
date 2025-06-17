package milt

import (
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emersion/go-milter"
	"go.uber.org/zap"
)

func TestEmailParsing(t *testing.T) {
	logger := zap.NewNop()
	e := MailProcessor(logger)
	defer e.Close()

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

	// Verify email file was created
	fileName := e.id + ".eml"
	path := filepath.Join("testdata", fileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected email file %s not found: %v", path, err)
	}
	os.Remove(path)

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
	e := MailProcessor(logger)
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
