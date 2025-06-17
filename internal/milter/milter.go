package milter

import (
	"context"
	"log"

	milter "github.com/emersion/go-milter"
	antimod "github.com/example/antispam/internal/antispam"
)

// Server wraps the go-milter library and delegates spam detection to Scorer.
type Server struct {
	addr   string
	scorer *antimod.Scorer
}

// NewServer creates a new Milter server.
func NewServer(addr string, scorer *antimod.Scorer) *Server {
	return &Server{addr: addr, scorer: scorer}
}

// Serve starts listening for connections from Postfix.
func (s *Server) Serve(ctx context.Context) error {
	srv := milter.Server{
		Addr: s.addr,
		// Each connection will create a session that implements the Handler interface.
		// Using inline struct for brevity.
		Factory: func() (milter.Milter, error) {
			return &session{scorer: s.scorer}, nil
		},
	}
	return srv.ListenAndServe(ctx)
}

type session struct {
	milter.Session
	scorer *antimod.Scorer
}

// Connect is called at the start of a new SMTP session.
func (s *session) Connect(ctx context.Context, c *milter.Connect) error {
	log.Printf("connect from %s", c.Host)
	return nil
}

// Headers returns continue to let Postfix send body.
func (s *session) Headers(ctx context.Context, h *milter.Headers) error {
	return nil
}

// Body is called with the full message body.
func (s *session) Body(ctx context.Context, b *milter.Body) error {
	msg := &antimod.Message{
		From:    b.MailFrom,
		Subject: b.Header.Get("Subject"),
		Body:    string(b.Bytes()),
	}
	if s.scorer.IsSpam(msg) {
		// Reject spam messages.
		return milter.NewResponse(550, 5, 7, "Message rejected as spam")
	}
	return nil
}
