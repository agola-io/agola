package util

import (
	"errors"
	"regexp"
)

var nameRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*([-]?[a-zA-Z0-9]+)+$`)

var (
	ErrValidation = errors.New("validation error")
)

func ValidateName(s string) bool {
	return nameRegexp.MatchString(s)
}
