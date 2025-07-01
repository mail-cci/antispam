package types

import "context"

// SPFLookupResult represents the result of an SPF lookup.
type SPFLookupResult struct {
	Result string
	TTL    uint32 // Time to live for the SPF record
}

// SPFResult holds information about SPF check results.
type SPFResult struct {
	Result string
	Domain string
	Score  float64
	// RecordTTL contains the minimum TTL among all evaluated SPF records.
	RecordTTL uint32
}

// DKIMSignatureResult represents the result of verifying a single DKIM signature
type DKIMSignatureResult struct {
	Valid         bool
	Domain        string
	Selector      string
	Algorithm     string   // Signing algorithm (rsa-sha256, etc.)
	HashAlgorithm string   // Hash algorithm (sha256, sha1, etc.)
	BodyLength    int64    // Length of body covered (-1 if entire body)
	Headers       []string // Headers included in signature
	WeakHash      bool     // True if using SHA-1
	KeyLength     int      // RSA key length in bits
	Error         string   // Error message if verification failed
	Timestamp     int64    // Signature timestamp if present
	Expiration    int64    // Signature expiration if present
}

// AlignmentCandidate represents a domain candidate for DMARC alignment
type AlignmentCandidate struct {
	Domain          string
	Selector        string
	Valid           bool
	AlignmentMode   string // "strict" or "relaxed"
	AlignmentResult string // "pass", "fail", or "none"
}

// DKIMAnomalyFlag represents different types of anomalies detected in DKIM signatures
type DKIMAnomalyFlag string

const (
	AnomalyNone                 DKIMAnomalyFlag = ""
	AnomalyMultipleValidDomains DKIMAnomalyFlag = "multiple_valid_domains"
	AnomalyMixedHashAlgorithms  DKIMAnomalyFlag = "mixed_hash_algorithms"
	// AnomalyWeakHashAlgorithm is triggered when signatures use weak hash algorithms like SHA-1
	AnomalyWeakHashAlgorithm     DKIMAnomalyFlag = "weak_hash_algorithm"
	AnomalyExpiredSignatures     DKIMAnomalyFlag = "expired_signatures"
	AnomalyFutureSignatures      DKIMAnomalyFlag = "future_signatures"
	AnomalyTooManySignatures     DKIMAnomalyFlag = "too_many_signatures"
	AnomalyWeakKeyLength         DKIMAnomalyFlag = "weak_key_length"
	AnomalyInconsistentSelectors DKIMAnomalyFlag = "inconsistent_selectors"
	AnomalyDomainMismatch        DKIMAnomalyFlag = "domain_mismatch"
	AnomalySignatureRollover     DKIMAnomalyFlag = "signature_rollover"
	AnomalySuspiciousHeaderCount DKIMAnomalyFlag = "suspicious_header_count"
)

// SecurityThreatLevel represents the security threat assessment
type SecurityThreatLevel string

const (
	ThreatNone     SecurityThreatLevel = "none"
	ThreatLow      SecurityThreatLevel = "low"
	ThreatMedium   SecurityThreatLevel = "medium"
	ThreatHigh     SecurityThreatLevel = "high"
	ThreatCritical SecurityThreatLevel = "critical"
)

// DKIMEdgeCaseInfo contains information about detected edge cases and anomalies
type DKIMEdgeCaseInfo struct {
	Anomalies         []DKIMAnomalyFlag   // List of detected anomalies
	ThreatLevel       SecurityThreatLevel // Overall threat assessment
	ThreatDescription string              // Human-readable threat description
	RecommendedAction string              // Suggested action based on analysis
	ConfidenceScore   float64             // Confidence in the anomaly detection (0-1)
}

// DKIMPerformanceInfo contains performance metrics for DKIM verification
type DKIMPerformanceInfo struct {
	ProcessingTime    int64   // Total processing time in microseconds
	DNSLookupTime     int64   // Time spent on DNS lookups in microseconds
	CacheHitRate      float64 // Cache hit rate (0-1)
	ParallelWorkers   int     // Number of parallel workers used
	EarlyTermination  bool    // Whether early termination was triggered
	SignaturesSkipped int     // Number of signatures skipped due to early termination
}

// DKIMCacheKey represents a cache key for DKIM operations
type DKIMCacheKey struct {
	Type     string // "signature", "key", "result"
	Domain   string
	Selector string
	Hash     string // Content hash for signature results
}

// DKIMCacheEntry represents a cached DKIM entry
type DKIMCacheEntry struct {
	Key        DKIMCacheKey
	Value      interface{}
	Expiration int64 // Unix timestamp
	TTL        int64 // TTL in seconds
	HitCount   int64 // Number of cache hits
	Size       int64 // Entry size in bytes
}

// DKIMWorkerPool configuration
type DKIMWorkerPoolConfig struct {
	WorkerCount       int  // Number of worker goroutines
	QueueSize         int  // Size of work queue
	DNSWorkerCount    int  // Number of DNS lookup workers
	EnableEarlyExit   bool // Enable early termination optimization
	EarlyExitMinValid int  // Minimum valid signatures before early exit
}

// DKIMResult represents DKIM verification outcomes for multiple signatures
type DKIMResult struct {
	Valid               bool                  // True if at least one signature is valid
	Domain              string                // Primary domain (first valid signature)
	Selector            string                // Primary selector (first valid signature)
	Score               float64               // Calculated score based on all signatures
	WeakHash            bool                  // True if any signature uses weak hash
	DomainAgreement     bool                  // True if all signatures agree on domain
	SelectorReuse       bool                  // True if a selector is reused across signatures
	RolloverDetected    bool                  // True if multiple selectors used for one domain
	Signatures          []DKIMSignatureResult // All signature verification results
	ValidSignatures     int                   // Count of valid signatures
	TotalSignatures     int                   // Total count of signatures found
	AlignmentCandidates []AlignmentCandidate  // Domains available for DMARC alignment
	BestSignature       *DKIMSignatureResult  // Best signature for scoring purposes
	EdgeCaseInfo        *DKIMEdgeCaseInfo     // Edge case and anomaly information
	PerformanceInfo     *DKIMPerformanceInfo  // Performance metrics and timing
}

// DMARCAlignmentMode represents DMARC alignment mode
type DMARCAlignmentMode string

const (
	AlignmentStrict  DMARCAlignmentMode = "s" // Strict alignment
	AlignmentRelaxed DMARCAlignmentMode = "r" // Relaxed alignment
)

// DMARCAlignmentResult represents the result of DMARC alignment checking
type DMARCAlignmentResult struct {
	SPFAligned  bool               // SPF domain alignment result
	DKIMAligned bool               // DKIM domain alignment result
	SPFMode     DMARCAlignmentMode // SPF alignment mode used
	DKIMMode    DMARCAlignmentMode // DKIM alignment mode used
	FromDomain  string             // Domain from From header
	SPFDomain   string             // Domain used for SPF alignment
	DKIMDomain  string             // Domain used for DKIM alignment
}

// DMARCPolicy represents DMARC policy information
type DMARCPolicy struct {
	Policy          string             // "none", "quarantine", "reject"
	SubdomainPolicy string             // Subdomain policy if different
	SPFAlignment    DMARCAlignmentMode // Required SPF alignment mode
	DKIMAlignment   DMARCAlignmentMode // Required DKIM alignment mode
	Percentage      int                // Policy application percentage (0-100)
	ReportURI       []string           // Aggregate report URIs (rua)
	ForensicURI     []string           // Forensic report URIs (ruf)
	Domain          string             // Domain this policy applies to
	TTL             uint32             // DNS record TTL
	
	// Additional RFC 7489 fields
	FailureOptions  []string           // Forensic report conditions (fo)
	ReportInterval  uint32             // Report interval in seconds (ri)
	Version         string             // DMARC version (v)
	
	// Parser metadata
	RawRecord       string             // Original DNS record for reference
	ParseErrors     []string           // Any parsing errors encountered
	UnknownTags     map[string]string  // Unknown tags found in record
}

// DMARCResult represents DMARC evaluation result
type DMARCResult struct {
	Valid       bool                  // Overall DMARC validation result
	Policy      *DMARCPolicy          // DMARC policy found
	Alignment   *DMARCAlignmentResult // Alignment check results
	Disposition string                // Final disposition ("none", "quarantine", "reject")
	Reason      []string              // Reasons for the disposition
	Score       float64               // DMARC contribution to spam score
	Error       string                // Error message if evaluation failed
	ReportInfo  *DMARCReportInfo      // Information for DMARC report generation
}

// OrganizationalDomain represents an organizational domain extraction result
type OrganizationalDomain struct {
	Domain         string // Original domain
	OrgDomain      string // Extracted organizational domain
	PublicSuffix   string // Public suffix (TLD)
	Subdomain      string // Subdomain part if any
	IsPublicSuffix bool   // Whether the domain is a public suffix itself
}

// DMARCQueryInterface defines the interface for DMARC DNS queries
type DMARCQueryInterface interface {
	// QueryPolicy retrieves DMARC policy for a domain
	QueryPolicy(ctx context.Context, domain string) (*DMARCPolicy, error)

	// QueryWithCache retrieves DMARC policy with caching
	QueryWithCache(ctx context.Context, domain string) (*DMARCPolicy, error)

	// GetOrganizationalDomain extracts organizational domain
	GetOrganizationalDomain(domain string) *OrganizationalDomain

	// CheckAlignment performs DMARC alignment checking
	CheckAlignment(fromDomain string, spfResult *SPFResult, dkimResult *DKIMResult, policy *DMARCPolicy) *DMARCAlignmentResult
}

// AuthResult aggregates SPF, DKIM, and DMARC results.
type AuthResult struct {
	SPF   SPFResult
	DKIM  DKIMResult
	DMARC DMARCResult
}

// EmailAnalysis stores authentication and scoring information for an email.
type EmailAnalysis struct {
	MessageID  string
	AuthResult AuthResult
	TotalScore float64
	Decision   string
}

// DMARCReportInfo contains information needed for DMARC report generation
type DMARCReportInfo struct {
	MessageID       string    // Email message ID
	SourceIP        string    // Source IP address
	MessageDate     int64     // Message timestamp
	EnvelopeFrom    string    // Envelope from address
	HeaderFrom      string    // Header from address
	PolicyDomain    string    // Domain that published the DMARC policy
	SPFDomain       string    // Domain used for SPF check
	DKIMDomain      string    // Domain used for DKIM check
	SPFResult       string    // SPF check result
	DKIMResult      string    // DKIM check result
	Disposition     string    // Applied disposition
	ReportGenerated bool      // Whether this should generate a report
}

// DMARCAggregateReportRecord represents a single record in DMARC aggregate reports
type DMARCAggregateReportRecord struct {
	SourceIP        string                 // Source IP address
	Count           int                    // Number of messages from this source
	Disposition     string                 // Disposition applied
	DMARCResult     string                 // Overall DMARC result
	SPFDomain       string                 // SPF domain
	SPFResult       string                 // SPF result
	SPFAlignment    DMARCAlignmentMode     // SPF alignment mode
	DKIMDomain      string                 // DKIM domain
	DKIMResult      string                 // DKIM result
	DKIMAlignment   DMARCAlignmentMode     // DKIM alignment mode
	HeaderFrom      string                 // From header domain
	EnvelopeFrom    string                 // Envelope from domain
	Reason          []string               // Policy override reasons
}

// DMARCForensicReport represents a DMARC forensic (failure) report
type DMARCForensicReport struct {
	MessageID       string    // Original message ID
	ReportID        string    // Unique report ID
	FeedbackType    string    // Type of feedback (auth-failure)
	UserAgent       string    // Reporting user agent
	Version         string    // Report format version
	OriginalDate    int64     // Original message date
	ArrivalDate     int64     // Message arrival date
	SourceIP        string    // Source IP address
	AuthFailure     []string  // Authentication failure types
	DeliveryResult  string    // Delivery result
	SPFFailure      string    // SPF failure reason
	DKIMFailure     string    // DKIM failure reason
	DMARCFailure    string    // DMARC failure reason
	OriginalMessage string    // Original message (headers/body)
	ReportURI       []string  // Where to send the report
}
