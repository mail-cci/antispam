package helpers

import "testing"

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		if got := ExtractDomain(tt.email); got != tt.expected {
			t.Errorf("ExtractDomain(%q) = %q, want %q", tt.email, got, tt.expected)
		}
	}
}

func TestGenerateCorrelationID(t *testing.T) {
	id1 := GenerateCorrelationID()
	if id1 == "" {
		t.Fatal("expected non-empty id")
	}
	id2 := GenerateCorrelationID()
	if id1 == id2 {
		t.Error("expected unique ids")
	}
}

func TestValidSender(t *testing.T) {
	valid := []string{"user@example.com", "a@b"}
	for _, v := range valid {
		if !ValidSender(v) {
			t.Errorf("ValidSender(%q) = false, want true", v)
		}
	}

	invalid := []string{"user@", "@example.com", "invalid", "user@domain@other"}
	for _, v := range invalid {
		if ValidSender(v) {
			t.Errorf("ValidSender(%q) = true, want false", v)
		}
	}
}
