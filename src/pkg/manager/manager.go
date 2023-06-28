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
	CheckStatus() (bool, error)
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
	GetCredential(name *credential.Name) (credential.Credential, error)
	DeleteCredential(name *credential.Name) error
	GetAllCredentials() ([]credential.Credential, error)
}

// list is a credential manager
type list struct {
	credentials map[credential.Name]credential.Credential
	timer       *timer.TimerManager
	masterKey   *password.EncryptedPassword
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
	if _, err = l.CheckStatus(); err != nil {
		return
	}

	cred, err := credential.NewSimpleCredential(request)

	if err != nil {
		return
	}
	name := cred.GetName()
	c = cred

	l.credentials[*name] = c

	err = l.timer.ResetTimer()

	return
}

// GetCredential returns a credential c and possible error err
func (l *list) GetCredential(name *credential.Name) (c credential.Credential, err error) {
	if _, err = l.CheckStatus(); err != nil {
		return
	}

	c, ok := l.credentials[*name]
	if !ok {
		return nil, fmt.Errorf("error getting credential: %w", exceptions.ErrCredentialNotFound)
	}

	err = l.timer.ResetTimer()

	return
}

// DeleteCredential deletes a credential c and possible error err
func (l *list) DeleteCredential(name *credential.Name) (err error) {
	if _, err = l.CheckStatus(); err != nil {
		return
	}

	_, err = l.GetCredential(name)

	if err != nil {
		return
	}

	delete(l.credentials, *name)

	err = l.timer.ResetTimer()

	return
}

// GetAllCredentials returns all credentials c and possible error err
func (l *list) GetAllCredentials() (credentials []credential.Credential, err error) {
	if _, err = l.CheckStatus(); err != nil {
		return
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

// InputMasterKey inputs the master key
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
func (l *list) CheckStatus() (ok bool, err error) {
	if ok, err = helpers.CheckTimer(l.timer); err != nil || ok {
		return false, fmt.Errorf("error checking status: %w", err)
	}

	return
}
