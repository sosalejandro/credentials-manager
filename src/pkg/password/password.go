package password

type ReadPassword interface {
	Get() string
}

type Password interface {
	Set(pr *Request) (ok bool, err error)
}

type EncryptionPassword interface {
	Hash(s string) ([]byte, error)
	VerifyPassword(s string) bool
}
