package helpers

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/credential"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"github.com/sosalejandro/credentials/src/pkg/manager"
	"github.com/sosalejandro/credentials/src/pkg/password"
)

func CheckEncryptionAndInputMasterKey(c credential.Credential, mk string, m manager.MasterOperator) (e bool, v bool) {
	e = c.IsEncrypted()
	v = !(mk == "")

	// if the credential is not encrypted or the master key is empty, return
	if e && !v {
		return
	}

	// if the credential is encrypted and the master key is not empty
	// check if the master key is valid
	if e {
		pw, err := password.NewPasswordRequest(mk)
		if err != nil {
			return e, !v
		}
		// if the master key is not valid, return an error
		if isKey, _ := m.InputMasterKey(&pw); !isKey {
			return e, !v
		}
	}

	return
}

func DecryptPassword(dpw password.ReadPassword, c credential.Credential) (dpr *password.Request, err error) {
	// decrypted password
	decryptPw, err := password.NewPasswordRequest(dpw.Get())

	if err != nil {
		return dpr, fmt.Errorf("error decrypting password: %w", err)
	}

	// create encrypted password
	cp, err := c.GetPassword()
	if err != nil {
		return dpr, fmt.Errorf("error decrypting password: %w", err)
	}

	epr, err := password.NewPasswordRequest(cp)
	if err != nil {
		return dpr, fmt.Errorf("error decrypting password: %w", err)
	}

	epw, err := password.NewEncryptedPassword(&epr)
	if err != nil {
		return dpr, fmt.Errorf("error decrypting password: %w", err)
	}

	if !epw.VerifyPassword(dpw.Get()) {
		return nil, fmt.Errorf("error decrypting password: %w", exceptions.ErrNotMatchingPassword)
	}

	dpr = &decryptPw

	return
}
