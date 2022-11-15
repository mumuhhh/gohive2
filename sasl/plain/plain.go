package saslplain

import (
	"errors"
	"fmt"
	"github.com/mumuhhh/gohive2/sasl"
)

type PlainClient struct {
	completed       bool
	authorizationID string
	username        string
	password        string
}

func NewPlainClient(authorizationID, username, password string) *PlainClient {
	return &PlainClient{
		authorizationID: authorizationID,
		username:        username,
		password:        password,
	}
}

func (p *PlainClient) GetMechanismName() string {
	return "PLAIN"
}

func (p *PlainClient) HasInitialResponse() bool {
	return true
}

func (p *PlainClient) EvaluateChallenge([]byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("PLAIN authentication already completed")
	}
	p.completed = true
	NULL := "\x00"
	return []byte(fmt.Sprintf("%s%s%s%s%s", p.authorizationID, NULL, p.username, NULL, p.password)), nil
}

func (p *PlainClient) IsComplete() bool {
	return p.completed
}

func (p *PlainClient) Unwrap([]byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("PLAIN supports neither integrity nor privacy")
	}
	return nil, errors.New("PLAIN authentication not completed")
}

func (p *PlainClient) Wrap([]byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("PLAIN supports neither integrity nor privacy")
	}
	return nil, errors.New("PLAIN authentication not completed")
}

func (p *PlainClient) GetNegotiatedProperty(propName string) (string, error) {
	if p.completed {
		if propName == "sasl.qop" {
			return "auth", nil
		} else {
			return "", nil
		}
	} else {
		return "", errors.New("PLAIN authentication not completed")
	}
}

func (p *PlainClient) Dispose() {
	p.password = ""
}

var _ sasl.Client = (*PlainClient)(nil)
