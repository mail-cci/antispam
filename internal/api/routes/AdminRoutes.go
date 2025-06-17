package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/mail-cci/antispam/pkg/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func AddAdminRoutes(r *gin.Engine) {
	r.POST("/log-level", func(c *gin.Context) {
		newLevel := c.Query("level")
		if err := logger.SetLevel(newLevel); err != nil {
			c.JSON(400, gin.H{"error": "Invalid level"})
			return
		}
		c.JSON(200, gin.H{"new_level": newLevel})
	})

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
}
