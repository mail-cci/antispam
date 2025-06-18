package scoring

import (
	"testing"

	"github.com/mail-cci/antispam/internal/config"
)

func TestDecide(t *testing.T) {
	cfg := &config.Config{Scoring: config.ScoringConfig{RejectThreshold: 10, QuarantineThreshold: 5}}
	Init(cfg)

	tests := []struct {
		score    float64
		expected string
	}{
		{11, "reject"},
		{10, "reject"},
		{7, "quarantine"},
		{5, "quarantine"},
		{4.9, "accept"},
		{0, "accept"},
	}

	for _, tt := range tests {
		if got := Decide(tt.score); got != tt.expected {
			t.Errorf("Decide(%v) = %q, want %q", tt.score, got, tt.expected)
		}
	}
}
