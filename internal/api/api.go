package api

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/mail-cci/antispam/internal/api/middleware"
	"github.com/mail-cci/antispam/internal/api/routes"
	"github.com/mail-cci/antispam/internal/config"
	"go.uber.org/zap"
)

var logger *zap.Logger

func InitLogger(l *zap.Logger) {
	logger = l
}

// NewServer creates and configures a new Gin server instance.
func NewServer(cfg *config.Config) *gin.Engine {
	// Set Gin mode based on configuration
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Create a Gin router
	router := gin.New()

	// Configure CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Adjust allowed origins as needed
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Add logging middleware
	router.Use(gin.Recovery(), middleware.LoggingMiddleware(logger, cfg.LogLevel))

	// Load routes from other páckage files
	routes.SetupRoutes(router)
	routes.AddAdminRoutes(router)

	return router
}
