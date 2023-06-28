package credential

import (
	"github.com/sosalejandro/credentials/src/pkg/password"
)

type CreateCredentialRequest struct {
	Name                 Name
	Account, Description string
	Password             *password.Request
	IsEncrypted          bool
}

type Credential interface {
	GetName() *Name
	GetAccount() string
	GetDescription() string
	GetPassword() (string, error)
	IsEncrypted() bool
}
