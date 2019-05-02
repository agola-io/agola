package util

import (
	"errors"
	"regexp"

	uuid "github.com/satori/go.uuid"
)

var nameRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*([-]?[a-zA-Z0-9]+)+$`)

var (
	ErrValidation = errors.New("validation error")
)

func ValidateName(s string) bool {
	// names that are valid uuids are not valid. This is needed to accept both
	// names or uuid in rest APIs
	if _, err := uuid.FromString(s); err == nil {
		return false
	}
	return nameRegexp.MatchString(s)
}
