package password

import (
	"fmt"
	"github.com/sosalejandro/credentials/src/pkg/exceptions"
)

type SimplePassword []byte

func NewSimplePassword(p *Request) (sp *SimplePassword, err error) {
	if p == nil {
		return nil, fmt.Errorf("error creating password: %w", exceptions.ErrPasswordEmpty)
	}

	sp = &SimplePassword{}
	if ok, err := sp.Set(p); !ok || err != nil {
		return nil, fmt.Errorf("error creating password: %w", err)
	}

	return
}

func (p *SimplePassword) Set(pr *Request) (ok bool, err error) {
	if ok, err = pr.ValidatePassword(); !ok || err != nil {
		return false, fmt.Errorf("error setting password: %w", err)
	}

	*p = []byte(*pr)

	return
}

func (p *SimplePassword) Get() string {
	return string(*p)
}
