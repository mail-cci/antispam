package types

// SPFResult holds information about SPF check results.
type SPFResult struct {
	Result      string
	Domain      string
	Explanation string
	Score       float64
}

// DKIMResult represents DKIM verification outcomes.
type DKIMResult struct {
	Valid    bool
	Domain   string
	Selector string
	Score    float64
}

// AuthResult aggregates SPF and DKIM results.
type AuthResult struct {
	SPF  SPFResult
	DKIM DKIMResult
}

// EmailAnalysis stores authentication and scoring information for an email.
type EmailAnalysis struct {
	MessageID  string
	AuthResult AuthResult
	TotalScore float64
	Decision   string
}
