package password

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"golang.org/x/crypto/bcrypt"
)

type EncryptedPassword []byte

func NewEncryptedPassword(p *Request) (*EncryptedPassword, error) {
	if p == nil {
		return nil, fmt.Errorf("error creating password: %w", exceptions.ErrPasswordEmpty)
	}

	password := &EncryptedPassword{}
	if ok, err := password.Set(p); !ok || err != nil {
		return nil, fmt.Errorf("error creating password: %w", err)
	}

	return password, nil
}

// Hash password into sha-512
func (p *EncryptedPassword) Hash(s string) ([]byte, error) {
	// implemented the sha-512 algorithm
	password := []byte(s)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}
	return hashedPassword, nil
}

func (p *EncryptedPassword) VerifyPassword(s string) bool {
	// Verify the password
	password := []byte(s)
	err := bcrypt.CompareHashAndPassword(*p, password)
	if err != nil {
		return false
	}

	return true
}

func (p *EncryptedPassword) Set(pr *Request) (ok bool, err error) {
	if ok, err = pr.ValidatePassword(); !ok || err != nil {
		return false, fmt.Errorf("error setting password: %w", err)
	}

	hashedPassword, err := p.Hash(string(*pr))
	if err != nil {
		return false, fmt.Errorf("error setting password: %w", err)
	}

	*p = hashedPassword

	return
}
