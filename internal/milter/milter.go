package milter

import (
	"context"
	"io"
	"log"
	"net"

	antimod "github.com/example/antispam/internal/antispam"
)

// Server provides a very small stub implementation that would normally expose
// a Milter compatible interface. It listens on the configured network/address
// and forwards the raw message body to the spam scorer.
type Server struct {
	network string
	addr    string
	scorer  *antimod.Scorer
}

// NewServer creates a new Milter server using the given network and address.
// Network is typically "tcp" or "unix".
func NewServer(network, addr string, scorer *antimod.Scorer) *Server {
	return &Server{network: network, addr: addr, scorer: scorer}
}

// Serve starts listening for connections from Postfix.
func (s *Server) Serve(ctx context.Context) error {
	l, err := net.Listen(s.network, s.addr)
	if err != nil {
		return err
	}
	defer l.Close()
	log.Printf("milter listening on %s %s", s.network, s.addr)

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				log.Printf("accept error: %v", err)
				continue
			}
		}

		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer c.Close()

	data, err := io.ReadAll(c)
	if err != nil {
		log.Printf("failed to read connection: %v", err)
		return
	}

	msg := &antimod.Message{Body: string(data)}
	if s.scorer.IsSpam(msg) {
		log.Printf("spam detected from %s", c.RemoteAddr())
	}
}
