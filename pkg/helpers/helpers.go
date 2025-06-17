package helpers

import (
	uuid "github.com/satori/go.uuid"
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

//func ValidSender(sender string) bool {
// Regular expression for validating an email address based on SMTP RFC
//const emailRegex = `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
//re := regexp.MustCompile(emailRegex)
//return re.MatchString(sender)
//}

func ValidSender(sender string) bool {
	parts := strings.Split(sender, "@")
	if len(parts) != 2 {
		return false
	}
	localPart := parts[0]
	domainPart := parts[1]
	return localPart != "" && domainPart != ""
}
