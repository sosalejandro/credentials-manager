package manager

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/credential"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
	"github.com/sosalejandro/credentials/src/pkg/helpers"
	"github.com/sosalejandro/credentials/src/pkg/password"
	"github.com/sosalejandro/timer"
	"github.com/sosalejandro/timer/domain"
	"time"
)

var (
	TimeDuration = 1 * time.Nanosecond
)

// CredentialManager defines the interface for a credential manager
type CredentialManager interface {
	Manager
	StatusHandler
}

// Manager defines the interface for a manager
type Manager interface {
	MasterOperator
	Operator
}

// StatusHandler defines the interface for a status handler
type StatusHandler interface {
	Unblock(mk string) error
	CheckStatus() (err error)
}

// MasterOperator defines the interface for a master key manager
type MasterOperator interface {
	CreateMasterKey(request *password.Request) (ok bool, err error)
	UpdateMasterKey(previous, request *password.Request) (ok bool, err error)
	InputMasterKey(request *password.Request) (ok bool, err error)
}

// Operator defines the interface for a credential operator
type Operator interface {
	CreateCredential(request credential.CreateCredentialRequest) (credential.Credential, error)
	GetCredential(name *credential.Name, mk string) (credential.Credential, error)
	DeleteCredential(name *credential.Name, mk string) error
	GetAllCredentials() ([]credential.Credential, error)
}

// encryptedList is a credential manager
type list struct {
	credentials   map[credential.Name]credential.Credential
	encryptedKeys map[credential.Name]password.SimplePassword
	timer         *timer.TimerManager
	masterKey     *password.EncryptedPassword
}

// NewCredentialManager creates a new credential manager cm and possible error err
func NewCredentialManager(mk *password.Request) (CredentialManager, error) {
	t, err := domain.NewTimer(TimeDuration)
	if err != nil {
		return nil, fmt.Errorf("error creating credential manager: %w", err)
	}

	ep, err := password.NewEncryptedPassword(mk)

	if err != nil {
		return nil, fmt.Errorf("error creating credential manager: %w", err)
	}

	cm := &list{
		credentials: make(map[credential.Name]credential.Credential),
		timer:       timer.NewTimerManager(t),
		masterKey:   ep,
	}

	if err = cm.timer.StartTimer(); err != nil {
		return nil, fmt.Errorf("error creating credential manager: %w", err)
	}

	return cm, nil
}

// CreateCredential creates a new credential c and possible error err
func (l *list) CreateCredential(request credential.CreateCredentialRequest) (c credential.Credential, err error) {
	if err = l.CheckStatus(); err != nil {
		return c, fmt.Errorf("error creating credential: %w", err)
	}
	cred, err := createCredential(request)

	if err != nil {
		return c, fmt.Errorf("error creating credential: %w", err)
	}
	name := cred.GetName()
	c = cred

	l.credentials[*name] = c

	err = l.timer.ResetTimer()

	if err != nil {
		delete(l.credentials, *name)
		return c, fmt.Errorf("error creating credential: %w", err)
	}

	return
}

// createCredential is a factory creational method for a credential
func createCredential(request credential.CreateCredentialRequest) (cred credential.Credential, err error) {
	if request.IsEncrypted {
		cred, err = credential.NewEncryptedCredential(request)
		return
	}
	cred, err = credential.NewSimpleCredential(request)
	return
}

// GetCredential returns a credential c and possible error err
func (l *list) GetCredential(name *credential.Name, mk string) (c credential.Credential, err error) {
	c, ok := l.credentials[*name]
	// check if the credential is encrypted and the master key is empty or invalid
	e, v := helpers.CheckEncryptionAndInputMasterKey(c, mk, l)
	if e && !v {
		goto masterKeyError
	}
	// if encrypted
	if e {
		// decrypt the password and assign it to the credential (simple credential)
		c, err = l.decryptPassword(name, c)
		if err != nil {
			return nil, fmt.Errorf("error getting credential: %w", err)
		}
		// if the credential was successfully decrypted
		// by pass the status check
		goto byPassStatus
	}
	// if not encrypted, check the status
	if err = l.CheckStatus(); err != nil {
		return nil, fmt.Errorf("error getting credential: %w", err)
	}
byPassStatus:
	// verify existence of the key, reset the timer and return credential
	if !ok {
		return nil, fmt.Errorf("error getting credential: %w", exceptions.ErrCredentialNotFound)
	}
	err = l.timer.ResetTimer()
	return
masterKeyError:
	return nil, fmt.Errorf("error getting credential: %w", exceptions.ErrInvalidMasterKey)
}

func (l *list) decryptPassword(name *credential.Name, c credential.Credential) (*credential.SimpleCredential, error) {
	// decrypted password
	decryptPw, ok := l.encryptedKeys[*name]
	if !ok {
		return nil, exceptions.ErrCredentialNotFound
	}

	dpr, err := helpers.DecryptPassword(&decryptPw, c)

	if err != nil {
		return nil, err
	}

	sc, _ := credential.NewSimpleCredential(credential.CreateCredentialRequest{
		Name:        *c.GetName(),
		Account:     c.GetAccount(),
		Description: c.GetDescription(),
		Password:    dpr,
		IsEncrypted: false,
	})

	return sc, err
}

// DeleteCredential deletes a credential c and possible error err
func (l *list) DeleteCredential(name *credential.Name, mk string) (err error) {
	if err = l.CheckStatus(); err != nil {
		return fmt.Errorf("error deleting credential: %w", err)
	}

	// refactor with just checking encryption and
	// avoid all flow of creating a struct to delete from list
	_, err = l.GetCredential(name, mk)

	if err != nil {
		return
	}

	delete(l.credentials, *name)

	err = l.timer.ResetTimer()

	return
}

// GetAllCredentials returns all credentials c and possible error err
func (l *list) GetAllCredentials() (credentials []credential.Credential, err error) {
	if err = l.CheckStatus(); err != nil {
		return credentials, fmt.Errorf("error getting all credentials: %w", err)
	}

	for _, c := range l.credentials {
		credentials = append(credentials, c)
	}

	err = l.timer.ResetTimer()

	return
}

// CreateMasterKey creates a new master key
func (l *list) CreateMasterKey(request *password.Request) (ok bool, err error) {
	ok, err = l.masterKey.Set(request)

	if err != nil {
		return
	}

	return
}

// UpdateMasterKey updates the master key
func (l *list) UpdateMasterKey(previous, request *password.Request) (ok bool, err error) {
	if ok, err = l.InputMasterKey(previous); err != nil {
		return false, fmt.Errorf("error updating master key: %w", err)
	}

	if ok, err = l.masterKey.Set(request); err != nil {
		return false, fmt.Errorf("error updating master key: %w", err)
	}

	return
}

// InputMasterKey inputs the master key and verifies it
func (l *list) InputMasterKey(request *password.Request) (ok bool, err error) {
	ok = l.masterKey.VerifyPassword(string(*request))

	if !ok {
		return false, fmt.Errorf("error inputting master key: %w", exceptions.ErrInvalidMasterKey)
	}

	return
}

// Unblock unblocks the timer
func (l *list) Unblock(mk string) (err error) {
	if err = helpers.UnblockTimer(mk, l.masterKey, l.timer); err != nil {
		return fmt.Errorf("error unblocking: %w", err)
	}

	return
}

// CheckStatus checks the status of the timer
func (l *list) CheckStatus() (err error) {
	if ok, err := helpers.CheckTimer(l.timer); err != nil || ok {
		return fmt.Errorf("error checking status: %w", err)
	}

	return
}
