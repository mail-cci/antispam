package api

import (
	"net/http"

	antispam "github.com/example/antispam/internal/antispam"
	"github.com/gin-gonic/gin"
)

// Server exposes a REST API to manage antispam configuration.
type Server struct {
	addr   string
	scorer *antispam.Scorer
}

// NewServer creates a new API server on the given address.
func NewServer(addr string, scorer *antispam.Scorer) *Server {
	return &Server{addr: addr, scorer: scorer}
}

// Run starts the HTTP server.
func (s *Server) Run() error {
	r := gin.Default()

	r.GET("/whitelist", func(c *gin.Context) {
		c.JSON(http.StatusOK, s.scorerWhitelist())
	})
	r.POST("/whitelist/:addr", func(c *gin.Context) {
		addr := c.Param("addr")
		s.scorer.AddToWhitelist(addr)
		c.Status(http.StatusCreated)
	})

	r.GET("/blacklist", func(c *gin.Context) {
		c.JSON(http.StatusOK, s.scorerBlacklist())
	})
	r.POST("/blacklist/:addr", func(c *gin.Context) {
		addr := c.Param("addr")
		s.scorer.AddToBlacklist(addr)
		c.Status(http.StatusCreated)
	})

	return r.Run(s.addr)
}

func (s *Server) scorerWhitelist() []string {
	res := make([]string, 0, len(s.scorer.Whitelist))
	for addr := range s.scorer.Whitelist {
		res = append(res, addr)
	}
	return res
}

func (s *Server) scorerBlacklist() []string {
	res := make([]string, 0, len(s.scorer.Blacklist))
	for addr := range s.scorer.Blacklist {
		res = append(res, addr)
	}
	return res
}
