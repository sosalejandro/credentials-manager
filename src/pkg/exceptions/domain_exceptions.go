package exceptions

type domainError struct {
	err string
}

func (e *domainError) Error() string {
	return e.err
}

var ErrPasswordTooShort = &domainError{err: "password is too short"}

var ErrPasswordEmpty = &domainError{err: "password field is empty"}

var ErrPasswordTooLong = &domainError{err: "password is too long"}

var ErrPasswordNoUppercase = &domainError{err: "password does not contain uppercase letters"}

var ErrPasswordNoLowercase = &domainError{err: "password does not contain lowercase letters"}

var ErrPasswordNoNumber = &domainError{err: "password does not contain numbers"}

var ErrPasswordNoSymbol = &domainError{err: "password does not contain symbols"}

var ErrCredentialNameEmpty = &domainError{err: "credential name field is empty"}

var ErrCredentialAccountEmpty = &domainError{err: "credential account field is empty"}

var ErrCredentialPasswordEmpty = &domainError{err: "credential password field is empty"}

var ErrCredentialNotFound = &domainError{err: "credential not found"}

var ErrInvalidMasterKey = &domainError{err: "invalid master key"}

var ErrTimerBlocked = &domainError{err: "timer is blocked"}

var ErrNotMatchingPassword = &domainError{err: "passwords do not match"}
