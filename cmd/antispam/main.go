// Package main implements the CCI Antispam email filtering system.
// This is a high-performance email filtering system that integrates with Postfix
// via the milter protocol to provide real-time spam detection and filtering.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-milter"
	"go.uber.org/zap"

	"github.com/mail-cci/antispam/internal/api"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/dkim"
	milt "github.com/mail-cci/antispam/internal/milter"
	"github.com/mail-cci/antispam/internal/scoring"
	"github.com/mail-cci/antispam/internal/spf"
	"github.com/mail-cci/antispam/pkg/logger"
)

// Application version and build information
const (
	AppVersion = "1.0.0"
	AppName    = "CCI Antispam"
)

// Global application state
var (
	cfg         *config.Config                             // Application configuration
	cfgMutex    sync.RWMutex                               // Mutex for thread-safe config access
	ctx, cancel = context.WithCancel(context.Background()) // Application context for graceful shutdown
	mainLog     *zap.Logger                                // Main application logger

	// Module-specific loggers for better log organization
	spfLog    *zap.Logger
	dkimLog   *zap.Logger
	milterLog *zap.Logger
	apiLog    *zap.Logger

	// Server management
	wg sync.WaitGroup // WaitGroup for graceful shutdown coordination
)

// main is the entry point of the antispam application.
// It initializes configuration, loggers, modules, and starts the servers.
func main() {
	// Initialize configuration
	if err := initConfig(); err != nil {
		fmt.Printf("Failed to initialize configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize all loggers
	if err := initLoggers(); err != nil {
		fmt.Printf("Failed to initialize loggers: %v\n", err)
		os.Exit(1)
	}
	defer syncLoggers()

	// Set global logger for packages that use zap.L()
	zap.ReplaceGlobals(mainLog)

	// Initialize antispam modules
	mainLog.Info("Initializing antispam modules")
	if err := initModules(); err != nil {
		mainLog.Fatal("Failed to initialize modules", zap.Error(err))
	}

	// Start servers in background goroutines
	startServers()

	// Log successful startup
	mainLog.Info("Application started successfully",
		zap.String("name", AppName),
		zap.String("version", AppVersion),
		zap.String("environment", cfg.Env),
		zap.String("milter_port", cfg.MilterPort),
		zap.String("api_port", cfg.ApiPort),
	)

	// Wait for shutdown signals
	handleShutdown()
}

// initConfig loads and validates the application configuration
func initConfig() error {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	return nil
}

// initLoggers creates and configures all application loggers
func initLoggers() error {
	var err error

	// Initialize main logger
	mainLog, err = createLogger("main.log")
	if err != nil {
		return fmt.Errorf("creating main logger: %w", err)
	}

	// Initialize module-specific loggers
	spfLog, err = createLogger("spf.log")
	if err != nil {
		return fmt.Errorf("creating SPF logger: %w", err)
	}

	dkimLog, err = createLogger("dkim.log")
	if err != nil {
		return fmt.Errorf("creating DKIM logger: %w", err)
	}

	milterLog, err = createLogger("milter.log")
	if err != nil {
		return fmt.Errorf("creating milter logger: %w", err)
	}

	apiLog, err = createLogger("api.log")
	if err != nil {
		return fmt.Errorf("creating API logger: %w", err)
	}

	return nil
}

// createLogger creates a logger with standard configuration for the given filename
func createLogger(filename string) (*zap.Logger, error) {
	logConfig := logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/" + filename,
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	}

	return logger.Init(logConfig)
}

// syncLoggers ensures all log buffers are flushed
func syncLoggers() {
	loggers := []*zap.Logger{mainLog, spfLog, dkimLog, milterLog, apiLog}
	for _, l := range loggers {
		if l != nil {
			_ = l.Sync()
		}
	}
}

// initModules initializes all antispam detection modules
func initModules() error {
	// Initialize SPF module
	spf.Init(cfg, spfLog)

	// Initialize DKIM module
	dkim.Init(cfg, dkimLog)

	// Initialize scoring module
	scoring.Init(cfg)

	return nil
}

// startServers launches both the milter and HTTP API servers
func startServers() {
	// Start milter server for email processing
	wg.Add(1)
	go func() {
		defer wg.Done()
		startMilterServer()
	}()

	// Start HTTP API server for management
	wg.Add(1)
	go func() {
		defer wg.Done()
		startHTTPServer()
	}()
}

// handleShutdown manages graceful application shutdown
func handleShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigChan:
			mainLog.Info("Signal received",
				zap.String("signal", sig.String()),
			)

			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				mainLog.Info("Initiating graceful shutdown")
				gracefulShutdown()
				return

			case syscall.SIGHUP:
				mainLog.Info("Reloading configuration")
				if err := reloadConfig(); err != nil {
					mainLog.Error("Failed to reload configuration", zap.Error(err))
				}
			}
		case <-ctx.Done():
			mainLog.Info("Context cancelled, shutting down")
			return
		}
	}
}

// gracefulShutdown performs a clean shutdown of all services
func gracefulShutdown() {
	// Cancel context to signal all goroutines to stop
	cancel()

	// Create a timeout context for shutdown operations
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Channel to track completion
	done := make(chan struct{})

	go func() {
		// Wait for all servers to stop
		wg.Wait()
		close(done)
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-done:
		mainLog.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		mainLog.Warn("Shutdown timeout exceeded, forcing exit")
	}
}

// reloadConfig handles configuration reload (SIGHUP)
func reloadConfig() error {
	mainLog.Info("Starting configuration reload")
	
	// 1. Load new configuration
	newCfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}
	
	// 2. Validate new configuration
	if err := validateConfig(newCfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	// 3. Thread-safe config update
	cfgMutex.Lock()
	oldCfg := cfg
	cfg = newCfg
	cfgMutex.Unlock()
	
	// 4. Check if logger configuration changed and reinitialize if needed
	if err := reloadLoggersIfChanged(oldCfg, newCfg); err != nil {
		mainLog.Error("Failed to reload loggers", zap.Error(err))
		// Continue with module reload even if logger reload fails
	}
	
	// 5. Reload modules with new configuration
	if err := reloadModules(); err != nil {
		// Rollback configuration on module reload failure
		cfgMutex.Lock()
		cfg = oldCfg
		cfgMutex.Unlock()
		return fmt.Errorf("failed to reload modules, configuration rolled back: %w", err)
	}
	
	mainLog.Info("Configuration reload completed successfully",
		zap.String("environment", cfg.Env),
		zap.String("log_level", cfg.LogLevel),
		zap.String("milter_port", cfg.MilterPort),
		zap.String("api_port", cfg.ApiPort),
	)
	
	return nil
}

// validateConfig performs basic validation on the configuration
func validateConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is nil")
	}
	
	// Validate required fields
	if cfg.MilterPort == "" {
		return fmt.Errorf("milter port is required")
	}
	
	if cfg.ApiPort == "" {
		return fmt.Errorf("API port is required")
	}
	
	if cfg.LogLevel == "" {
		return fmt.Errorf("log level is required")
	}
	
	if cfg.LogPath == "" {
		return fmt.Errorf("log path is required")
	}
	
	// Validate log level is valid
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[cfg.LogLevel] {
		return fmt.Errorf("invalid log level: %s", cfg.LogLevel)
	}
	
	return nil
}

// reloadLoggersIfChanged reinitializes loggers if logging configuration changed
func reloadLoggersIfChanged(oldCfg, newCfg *config.Config) error {
	// Check if any logger-related configuration changed
	if oldCfg.LogLevel == newCfg.LogLevel && 
	   oldCfg.LogPath == newCfg.LogPath && 
	   oldCfg.Env == newCfg.Env {
		mainLog.Debug("Logger configuration unchanged, skipping logger reload")
		return nil
	}
	
	mainLog.Info("Logger configuration changed, reinitializing loggers",
		zap.String("old_level", oldCfg.LogLevel),
		zap.String("new_level", newCfg.LogLevel),
		zap.String("old_path", oldCfg.LogPath),
		zap.String("new_path", newCfg.LogPath),
	)
	
	// Sync old loggers before replacing them
	syncLoggers()
	
	// Create new loggers with updated configuration
	var err error
	
	// Store old loggers for rollback if needed
	oldMainLog := mainLog
	oldSpfLog := spfLog
	oldDkimLog := dkimLog
	oldMilterLog := milterLog
	oldApiLog := apiLog
	
	// Initialize new loggers
	mainLog, err = createLogger("main.log")
	if err != nil {
		return fmt.Errorf("failed to create new main logger: %w", err)
	}
	
	spfLog, err = createLogger("spf.log")
	if err != nil {
		// Rollback main logger
		mainLog = oldMainLog
		return fmt.Errorf("failed to create new SPF logger: %w", err)
	}
	
	dkimLog, err = createLogger("dkim.log")
	if err != nil {
		// Rollback previous loggers
		mainLog = oldMainLog
		spfLog = oldSpfLog
		return fmt.Errorf("failed to create new DKIM logger: %w", err)
	}
	
	milterLog, err = createLogger("milter.log")
	if err != nil {
		// Rollback previous loggers
		mainLog = oldMainLog
		spfLog = oldSpfLog
		dkimLog = oldDkimLog
		return fmt.Errorf("failed to create new milter logger: %w", err)
	}
	
	apiLog, err = createLogger("api.log")
	if err != nil {
		// Rollback previous loggers
		mainLog = oldMainLog
		spfLog = oldSpfLog
		dkimLog = oldDkimLog
		milterLog = oldMilterLog
		return fmt.Errorf("failed to create new API logger: %w", err)
	}
	
	// Update global logger for packages that use zap.L()
	zap.ReplaceGlobals(mainLog)
	
	// Close old loggers
	_ = oldMainLog.Sync()
	_ = oldSpfLog.Sync()
	_ = oldDkimLog.Sync()
	_ = oldMilterLog.Sync()
	_ = oldApiLog.Sync()
	
	mainLog.Info("Loggers successfully reinitialized")
	return nil
}

// reloadModules reinitializes all modules with the new configuration
func reloadModules() error {
	mainLog.Info("Reloading antispam modules with new configuration")
	
	// Thread-safe config access
	cfgMutex.RLock()
	currentCfg := cfg
	cfgMutex.RUnlock()
	
	// Reinitialize SPF module
	spf.Init(currentCfg, spfLog)
	spfLog.Info("SPF module reloaded")
	
	// Reinitialize DKIM module
	dkim.Init(currentCfg, dkimLog)
	dkimLog.Info("DKIM module reloaded")
	
	// Reinitialize scoring module
	scoring.Init(currentCfg)
	mainLog.Info("Scoring module reloaded")
	
	mainLog.Info("All modules successfully reloaded")
	return nil
}

// startMilterServer initializes and starts the milter server for email processing
func startMilterServer() {
	milt.Init(milterLog)
	server := milter.Server{
		NewMilter: func() milter.Milter {
			return milt.MailProcessor()
		},
		Actions: milter.OptAddHeader | milter.OptChangeHeader | milter.OptChangeFrom,
	}

	ln, err := net.Listen("tcp", ":"+cfg.MilterPort)
	if err != nil {
		milterLog.Fatal("Failed to start milter server",
			zap.Error(err),
			zap.String("port", cfg.MilterPort),
		)
	}

	milterLog.Info("Milter server running",
		zap.String("port", cfg.MilterPort),
		zap.String("network", "tcp"),
	)

	if err := server.Serve(ln); err != nil {
		milterLog.Error("Milter server failure",
			zap.Error(err),
			zap.String("phase", "operation"),
		)
	}
}

// startHTTPServer initializes and starts the HTTP API server for management operations
func startHTTPServer() {
	// Initialize API logger
	api.InitLogger(apiLog)

	// Create HTTP server with configuration
	server := api.NewServer(cfg)

	apiLog.Info("HTTP API server starting",
		zap.String("port", cfg.ApiPort),
		zap.String("mode", cfg.Env),
		zap.String("address", ":"+cfg.ApiPort),
	)

	// Start server and handle any startup errors
	if err := server.Run(":" + cfg.ApiPort); err != nil {
		apiLog.Error("HTTP API server failed to start",
			zap.Error(err),
			zap.String("port", cfg.ApiPort),
		)
	}
}
