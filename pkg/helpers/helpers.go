package helpers

import (
	uuid "github.com/satori/go.uuid"
	"regexp"
	"strings"
)

func ExtractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

func GenerateCorrelationID() string {
	return uuid.NewV4().String()
}

func isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

	if len(domain) > 253 {
		return false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}

	return domainRegex.MatchString(domain)
}

func ValidSender(sender string) bool {
	parts := strings.Split(sender, "@")
	if len(parts) != 2 {
		return false
	}
	localPart := parts[0]
	domainPart := parts[1]
	return localPart != "" && domainPart != ""
}
