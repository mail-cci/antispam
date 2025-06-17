package routes

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

// SetupRoutes defines all the API routes.
func SetupRoutes(router *gin.Engine) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Agrega más rutas aquí
	router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"version": "1.0.0"})
	})
}
