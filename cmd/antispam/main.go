package main

import (
	"context"
	"fmt"
	"github.com/emersion/go-milter"
	"github.com/mail-cci/antispam/internal/api"
	"github.com/mail-cci/antispam/internal/config"
	milt "github.com/mail-cci/antispam/internal/milter"
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
		FilePath:      cfg.LogPath + "/mail.log",
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
	defer func() {
		err := logger.Sync()
		if err != nil {
			log.Error("Error flushing logs", zap.Error(err))
		}
	}()

	zap.ReplaceGlobals(log)

	go startMilterServer(log)
	go startHTTPServer(log)

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

func startMilterServer(log *zap.Logger) {
	server := milter.Server{
		NewMilter: func() milter.Milter {
			return milt.MailProcessor(log.With(zap.String("component", "milter")))
		},
		Actions: milter.OptAddHeader | milter.OptChangeHeader | milter.OptChangeFrom,
	}

	ln, err := net.Listen("tcp", ":"+cfg.MilterPort)
	if err != nil {
		log.Fatal("Failed to start milter server",
			zap.Error(err),
			zap.String("port", cfg.MilterPort),
		)
	}

	log.Info("Milter server running",
		zap.String("port", cfg.MilterPort),
		zap.String("network", "tcp"),
	)

	if err := server.Serve(ln); err != nil {
		log.Error("Milter server failure",
			zap.Error(err),
			zap.String("phase", "operation"),
		)
	}
}

func startHTTPServer(log *zap.Logger) {
	r := api.NewServer(cfg, log.With(zap.String("component", "api")))

	log.Info("HTTP server starting",
		zap.String("port", cfg.ApiPort),
		zap.String("mode", cfg.Env),
	)

	if err := r.Run(":" + cfg.ApiPort); err != nil {
		log.Error("HTTP server failed",
			zap.Error(err),
			zap.String("phase", "startup"),
		)
	}
}
