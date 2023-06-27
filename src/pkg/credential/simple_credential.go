package credential

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"github.com/sosalejandro/credentials/src/pkg/password"
)

type SimpleCredential struct {
	name                 *Name
	account, description string
	password             password.ReadPassword
}

func NewSimpleCredential(request CreateCredentialRequest) (*SimpleCredential, error) {
	if request.Name == "" {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialNameEmpty)
	}

	if request.Account == "" {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialAccountEmpty)
	}

	if request.Password == nil {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialPasswordEmpty)
	}

	pw, err := password.NewSimplePassword(request.Password)

	if err != nil {
		return nil, fmt.Errorf("error creating credential: %w", err)
	}

	credential := &SimpleCredential{
		name:        &request.Name,
		account:     request.Account,
		description: request.Description,
		password:    pw,
	}

	return credential, nil
}

func (c *SimpleCredential) GetName() *Name {
	return c.name
}

func (c *SimpleCredential) GetAccount() string {
	return c.account
}

func (c *SimpleCredential) GetDescription() string {
	return c.description
}

func (c *SimpleCredential) GetPassword() (pw string, err error) {
	if _, ok := c.password.(password.ReadPassword); !ok {
		return "", fmt.Errorf("error getting password: %w", exceptions.ErrPasswordEmpty)
	}

	pw = c.password.Get()

	return
}
