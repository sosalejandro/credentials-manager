package password

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"regexp"
)

var (
	upper  = regexp.MustCompile(`[A-Z]`)
	lower  = regexp.MustCompile(`[a-z]`)
	number = regexp.MustCompile(`[0-9]`)
	symbol = regexp.MustCompile(`[^a-zA-Z0-9\s]`)
)

type Request []byte

func NewPasswordRequest(password string) (pr Request, err error) {
	if password == "" {
		return pr, fmt.Errorf("error creating password request 1: %w", exceptions.ErrPasswordEmpty)
	}

	if len(password) < 8 {
		return pr, fmt.Errorf("error creating password request 2: %w", exceptions.ErrPasswordTooShort)
	}

	pr = []byte(password)

	if ok, err := pr.ValidatePassword(); !ok {
		return pr, fmt.Errorf("error creating password request 3: %w", err)
	}

	return
}

func (pr *Request) ValidatePassword() (ok bool, err error) {
	s := string(*pr)
	// Check if the string is between 8 and 1024 characters long
	if len(s) > 1024 {
		return false, fmt.Errorf("error validating password: %w", exceptions.ErrPasswordTooLong)
	}

	// Check if the string contains at least one uppercase letter
	if !upper.MatchString(s) {
		return false, fmt.Errorf("error validating password: %w", exceptions.ErrPasswordNoUppercase)
	}

	// Check if the string contains at least one lowercase letter
	if !lower.MatchString(s) {
		return false, fmt.Errorf("error validating password: %w", exceptions.ErrPasswordNoLowercase)
	}

	// Check if the string contains at least one number
	if !number.MatchString(s) {
		return false, fmt.Errorf("error validating password: %w", exceptions.ErrPasswordNoNumber)
	}

	// Check if the string contains at least one symbol
	if !symbol.MatchString(s) {
		return false, fmt.Errorf("error validating password: %w", exceptions.ErrPasswordNoSymbol)
	}

	return true, nil
}
