package main

import (
	"context"
	"fmt"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/internal/api"
	"github.com/mail-cci/antispam/internal/config"
	"github.com/mail-cci/antispam/internal/dkim"
	milt "github.com/mail-cci/antispam/internal/milter"
	"github.com/mail-cci/antispam/internal/scoring"
	"github.com/mail-cci/antispam/internal/spf"
	"github.com/mail-cci/antispam/pkg/logger"
	"go.uber.org/zap"
	"net"
	"os"
	"os/signal"
	"syscall"
)

var (
	cfg         *config.Config
	ctx, cancel = context.WithCancel(context.Background())
	spfLog      *zap.Logger
	dkimLog     *zap.Logger
	milterLog   *zap.Logger
	apiLog      *zap.Logger
)

func main() {
	var err error
	cfg, err = config.LoadConfig()
	if err != nil {
		fmt.Println("Error loading configuration:", err)
		os.Exit(1)
	}

	//  logger
	logConfig := logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/main.log",
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	}

	log, err := logger.Init(logConfig)
	if err != nil {
		fmt.Println("Error initializing logger:", err)
		os.Exit(1)
	}

	spfLog, _ = logger.Init(logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/spf.log",
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	})

	dkimLog, _ = logger.Init(logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/dkim.log",
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	})

	milterLog, _ = logger.Init(logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/milter.log",
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	})

	apiLog, _ = logger.Init(logger.LogConfig{
		Level:         cfg.LogLevel,
		FilePath:      cfg.LogPath + "/api.log",
		MaxSizeMB:     100,
		MaxBackups:    7,
		MaxAgeDays:    30,
		ConsoleOutput: cfg.Env == "development",
	})
	defer func() {
		_ = log.Sync()
		_ = spfLog.Sync()
		_ = dkimLog.Sync()
		_ = milterLog.Sync()
		_ = apiLog.Sync()
	}()

	zap.ReplaceGlobals(log)

	// Initialize modules with configuration
	log.Info("Initializing modules")
	spf.Init(cfg, spfLog)
	dkim.Init(cfg, dkimLog)
	scoring.Init(cfg)

	go startMilterServer()
	go startHTTPServer()

	log.Info("Application started",
		zap.String("version", "1.0.0"),
		zap.String("environment", cfg.Env),
		zap.Any("config", cfg),
	)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigChan:
			log.Info("Signal received",
				zap.String("signal", sig.String()),
				zap.Stack("stack_trace"),
			)

			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				cancel()
				log.Info("Graceful shutdown initiated")
				// TODO: Add cleanup logic here
				return

			case syscall.SIGHUP:
				log.Info("Reloading configuration")
				//TODO: Add configuration reload logic here
			}
		}
	}
}

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

func startHTTPServer() {
	api.InitLogger(apiLog)
	r := api.NewServer(cfg)
	apiLog.Info("HTTP server starting",
		zap.String("port", cfg.ApiPort),
		zap.String("mode", cfg.Env),
	)

	if err := r.Run(":" + cfg.ApiPort); err != nil {
		apiLog.Error("HTTP server failed",
			zap.Error(err),
			zap.String("phase", "startup"),
		)
	}
}
