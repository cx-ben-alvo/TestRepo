package service

import "strings"

// DomainValidator handles domain whitelist validation
type DomainValidator struct {
	allowedDomains []string
}

// NewDomainValidator creates a new domain validator
func NewDomainValidator() *DomainValidator {
	return &DomainValidator{
		allowedDomains: []string{
			"github.com",
			"gitlab.com",
			"https://github.com",
			"https://gitlab.com",
			"git@github.com",
			"git@gitlab.com",
		},
	}
}

// IsWhitelisted checks if the given URL contains a whitelisted domain
func (v *DomainValidator) IsWhitelisted(gitURL string) bool {
	gitURL = strings.ToLower(gitURL)
	for _, domain := range v.allowedDomains {
		if strings.Contains(gitURL, domain) {
			return true
		}
	}
	return false
}
