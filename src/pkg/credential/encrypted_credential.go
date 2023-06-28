package credential

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"github.com/sosalejandro/credentials/src/pkg/password"
)

type EncryptedCredential struct {
	name                 *Name
	account, description string
	password             password.EncryptionPassword
}

func NewEncryptedCredential(request CreateCredentialRequest) (*EncryptedCredential, error) {
	if request.Name == "" {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialNameEmpty)
	}

	if request.Account == "" {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialAccountEmpty)
	}

	if request.Password == nil {
		return nil, fmt.Errorf("error creating credential: %w", exceptions.ErrCredentialPasswordEmpty)
	}

	pw, err := password.NewEncryptedPassword(request.Password)

	if err != nil {
		return nil, fmt.Errorf("error creating credential: %w", err)
	}

	credential := &EncryptedCredential{
		name:        &request.Name,
		account:     request.Account,
		description: request.Description,
		password:    pw,
	}

	return credential, nil
}

func (c *EncryptedCredential) GetName() *Name {
	return c.name
}

func (c *EncryptedCredential) GetAccount() string {
	return c.account
}

func (c *EncryptedCredential) GetDescription() string {
	return c.description
}

func (c *EncryptedCredential) GetPassword() (pw string, err error) {
	if _, ok := c.password.(password.ReadPassword); !ok {
		return "", fmt.Errorf("error getting password: %w", exceptions.ErrPasswordEmpty)
	}

	pw = c.password.Get()

	return
}

func (c *EncryptedCredential) IsEncrypted() bool {
	return true
}
