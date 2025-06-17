package middleware

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func LoggingMiddleware(logger *zap.Logger, logLevel string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method
		body := c.Request.Body

		// Log request based on log level
		if logLevel == "info" {
			logger.Info("Incoming request",
				zap.String("method", method),
				zap.String("path", path),
				zap.Any("body", body),
			)
		}

		// Log headers only if log level is debug
		if logLevel == "debug" {
			headers := c.Request.Header
			logger.Debug("Incoming request",
				zap.String("method", method),
				zap.String("path", path),
				zap.Any("headers", headers),
				zap.Any("body", body),
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
				zap.Any("body", body),
				zap.Any("headers", c.Writer.Header()),
			)
		}
	}
}
