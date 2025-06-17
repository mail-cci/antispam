package middleware

import (
	"bytes"
	"io"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func LoggingMiddleware(logger *zap.Logger, logLevel string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method

		// Read and restore the request body so it can be consumed later
		var bodyBytes []byte
		if c.Request.Body != nil {
			b, err := io.ReadAll(c.Request.Body)
			if err == nil {
				bodyBytes = b
				c.Request.Body = io.NopCloser(bytes.NewBuffer(b))
			} else {
				logger.Error("failed to read request body", zap.Error(err))
			}
		}

		// Capture response body using a custom writer
		blw := &bodyLogWriter{body: bytes.NewBuffer(nil), ResponseWriter: c.Writer}
		c.Writer = blw

		const maxLoggedBody = 1024

		// Log request based on log level
		if logLevel == "info" {
			logger.Info("Incoming request",
				zap.String("method", method),
				zap.String("path", path),
			)
		}

		// Log headers only if log level is debug
		if logLevel == "debug" {
			headers := c.Request.Header
			logger.Debug("Incoming request",
				zap.String("method", method),
				zap.String("path", path),
				zap.Any("headers", headers),
				zap.String("body", string(truncateBody(bodyBytes, maxLoggedBody))),
			)
		}

		// Process the request
		c.Next()

		// Log response based on log level
		statusCode := c.Writer.Status()
		if logLevel == "info" {
			logger.Info("Response sent",
				zap.Int("status", statusCode),
				zap.String("path", path),
			)
		}

		// Log response body only if log level is debug
		if logLevel == "debug" {
			logger.Debug("Response sent",
				zap.Int("status", statusCode),
				zap.String("path", path),
				zap.String("body", string(truncateBody(blw.body.Bytes(), maxLoggedBody))),
				zap.Any("headers", c.Writer.Header()),
			)
		}
	}
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	if w.body != nil {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w bodyLogWriter) WriteString(s string) (int, error) {
	if w.body != nil {
		w.body.WriteString(s)
	}
	return w.ResponseWriter.WriteString(s)
}

func truncateBody(body []byte, limit int) []byte {
	if len(body) > limit {
		return append(body[:limit], []byte("...")...)
	}
	return body
}
