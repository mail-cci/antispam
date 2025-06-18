package scoring

import "github.com/mail-cci/antispam/internal/config"

var (
	RejectThreshold     float64 = 10.0
	QuarantineThreshold float64 = 5.0
)

// Init sets the scoring thresholds from the provided configuration.
func Init(cfg *config.Config) {
	if cfg == nil {
		return
	}
	RejectThreshold = cfg.Scoring.RejectThreshold
	QuarantineThreshold = cfg.Scoring.QuarantineThreshold
}

// Decide returns "reject", "quarantine" or "accept" based on the score
// compared against the configured thresholds.
func Decide(score float64) string {
	if score >= RejectThreshold {
		return "reject"
	}
	if score >= QuarantineThreshold {
		return "quarantine"
	}
	return "accept"
}
