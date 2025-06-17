package antispam

import "strings"

// Message represents minimal information about an email used for scoring.
type Message struct {
	From    string
	Subject string
	Body    string
}

// Scorer applies heuristic scoring to detect spam.
type Scorer struct {
	Keywords  map[string]int
	Threshold int
	Whitelist map[string]struct{}
	Blacklist map[string]struct{}
}

// NewScorer creates a new Scorer with default settings.
func NewScorer() *Scorer {
	return &Scorer{
		Keywords:  map[string]int{"buy now": 5, "free": 3},
		Threshold: 5,
		Whitelist: make(map[string]struct{}),
		Blacklist: make(map[string]struct{}),
	}
}

// AddToWhitelist adds an address to the whitelist.
func (s *Scorer) AddToWhitelist(addr string) { s.Whitelist[addr] = struct{}{} }

// AddToBlacklist adds an address to the blacklist.
func (s *Scorer) AddToBlacklist(addr string) { s.Blacklist[addr] = struct{}{} }

// Score calculates a spam score for the message.
func (s *Scorer) Score(msg *Message) int {
	if _, ok := s.Whitelist[msg.From]; ok {
		return 0
	}
	if _, ok := s.Blacklist[msg.From]; ok {
		return s.Threshold
	}
	score := 0
	text := msg.Subject + " " + msg.Body
	for kw, val := range s.Keywords {
		if containsIgnoreCase(text, kw) {
			score += val
		}
	}
	return score
}

// IsSpam returns true if the score is above the threshold.
func (s *Scorer) IsSpam(msg *Message) bool { return s.Score(msg) >= s.Threshold }

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
