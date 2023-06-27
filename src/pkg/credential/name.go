package credential

// Name is the name of a credential
type Name string

func (n Name) String() string {
	return string(n)
}
