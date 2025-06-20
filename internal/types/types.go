package types

// SPFLookupResult represents the result of an SPF lookup.
type SPFLookupResult struct {
	Result string
	TTL    uint32 // Time to live for the SPF record
}

// SPFResult holds information about SPF check results.
type SPFResult struct {
	Result      string
	Domain      string
	Explanation string
	Score       float64
	// RecordTTL contains the minimum TTL among all evaluated SPF records.
	RecordTTL uint32
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
