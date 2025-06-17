package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/example/antispam/config"
	am "github.com/example/antispam/internal/antispam"
	"github.com/example/antispam/internal/api"
	"github.com/example/antispam/internal/milter"
)

func main() {
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	scorer := am.NewScorer()

	apiSrv := api.NewServer(cfg.API.Addr, scorer)
	milterSrv := milter.NewServer(cfg.Milter.Network, cfg.Milter.Addr, scorer)

	// Run API in separate goroutine
	go func() {
		if err := apiSrv.Run(); err != nil {
			log.Fatalf("api server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := milterSrv.Serve(ctx); err != nil {
		log.Fatalf("milter error: %v", err)
	}
}
