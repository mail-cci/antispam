// internal/api/middleware/metrics.go
package middleware

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mail-cci/antispam/internal/metrics"
)

func PrometheusMetrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		method := c.Request.Method

		c.Next()

		duration := time.Since(start).Seconds()
		status := c.Writer.Status()

		metrics.APIDuration.WithLabelValues(path, method, statusCodeToString(status)).Observe(duration)
	}
}

func statusCodeToString(code int) string {
	return fmt.Sprintf("%d", code)
}
