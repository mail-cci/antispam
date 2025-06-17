package config

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("unable to get working dir: %v", err)
	}
	// move to project root so config.yaml can be found
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	defer os.Chdir(cwd)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if cfg.ApiPort != "8081" {
		t.Errorf("expected ApiPort 8081, got %s", cfg.ApiPort)
	}
	if cfg.MilterPort != "4829" {
		t.Errorf("expected MilterPort 4829, got %s", cfg.MilterPort)
	}
	if cfg.Env == "" {
		t.Error("expected Env to be set")
	}
}
