package saslgsskerb

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mumuhhh/gohive2/sasl"

	krb "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

type GssKerbClient struct {
	authzID        string
	protocol       string
	serverName     string
	kerberosClient *krb.Client

	completed, finalHandshake, privacy, integrity bool
	sessionKey                                    types.EncryptionKey
}

func NewGssKerbClient(authzID, protocol, serverName string, kerberosClient *krb.Client) *GssKerbClient {
	return &GssKerbClient{
		authzID:        authzID,
		protocol:       protocol,
		serverName:     serverName,
		kerberosClient: kerberosClient,
	}
}

func (p *GssKerbClient) GetMechanismName() string {
	return "GSSAPI"
}

func (p *GssKerbClient) HasInitialResponse() bool {
	return true
}

func (p *GssKerbClient) EvaluateChallenge(challenge []byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("GSSAPI authentication already completed")
	}

	if !p.finalHandshake {
		ticket, key, err := p.kerberosClient.GetServiceTicket(p.protocol + "/" + p.serverName)
		if err != nil {
			return nil, err
		}
		p.sessionKey = key
		token, err := spnego.NewNegTokenInitKRB5(p.kerberosClient, ticket, key)
		if err != nil {
			return nil, err
		}
		p.finalHandshake = true
		return token.MechTokenBytes, err

	} else {
		if len(challenge) == 0 {
			return make([]byte, 0), nil
		}
		data, err := p._unwrap(challenge, false)
		if err != nil {
			return nil, err
		}
		if len(data) != 4 {
			return nil, fmt.Errorf("decoded data should have length for at this stage")
		}
		qopBits := data[0]
		data[0] = 0
		serverMaxLength := int(binary.BigEndian.Uint32(data))

		switch qopBits {
		case 2:
			p.integrity = true
		case 4:
			p.integrity = true
			p.privacy = true
		}

		header := make([]byte, 4)
		maxLength := serverMaxLength
		if serverMaxLength > 65536 {
			maxLength = 65536
		}

		headerInt := (uint(qopBits) << 24) | uint(maxLength)

		binary.BigEndian.PutUint32(header, uint32(headerInt))

		// FLAG_BYTE + 3 bytes of length + user or authority
		var name string
		if p.authzID != "" {
			name = p.authzID
		}
		out := append(header, []byte(name)...)
		signed, err := p._wrap(out, false)
		if err != nil {
			return nil, err
		}
		p.completed = true
		return signed, err
	}
}

func (p *GssKerbClient) IsComplete() bool {
	return p.completed
}

func (p *GssKerbClient) _unwrap(b []byte, privacyState bool) ([]byte, error) {
	var wrapToken gssapi.WrapToken
	err := wrapToken.Unmarshal(b, true)
	if err != nil {
		return nil, err
	}

	if privacyState {
		// Decrypt the blob, which then looks like a normal RPC response.
		return crypto.DecryptMessage(wrapToken.Payload, p.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	} else {
		_, err = wrapToken.Verify(p.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if err != nil {
			return nil, fmt.Errorf("unverifiable message from server: %s", err)
		}
		return wrapToken.Payload, err
	}
}

func (p *GssKerbClient) Unwrap(incoming []byte) ([]byte, error) {
	if !p.completed {
		return nil, errors.New("GSSAPI authentication not completed")
	}
	if !p.integrity {
		return nil, errors.New("no security layer negotiated")
	}
	return p._unwrap(incoming, p.privacy)
}

func (p GssKerbClient) _wrap(b []byte, privacyState bool) ([]byte, error) {
	var payload = b
	if privacyState {
		et, err := crypto.GetEtype(p.sessionKey.KeyType)
		if err != nil {
			return nil, fmt.Errorf("error getting etype: %v", err)
		}
		_, x, err := et.EncryptMessage(p.sessionKey.KeyValue, b, keyusage.GSSAPI_INITIATOR_SEAL)
		if err != nil {
			return nil, err
		}
		payload = x
	}
	signed, err := gssapi.NewInitiatorWrapToken(payload, p.sessionKey)
	if err != nil {
		return nil, err
	}
	return signed.Marshal()
}

func (p *GssKerbClient) Wrap(outgoing []byte) ([]byte, error) {
	if !p.completed {
		return nil, errors.New("GSSAPI authentication not completed")
	}
	if !p.integrity {
		return nil, errors.New("no security layer negotiated")

	}
	return p._wrap(outgoing, p.privacy)
}

func (p *GssKerbClient) GetNegotiatedProperty(propName string) (string, error) {
	if p.completed {
		if propName == "sasl.qop" {
			if p.privacy {
				return sasl.QopPrivacy, nil
			} else if p.integrity {
				return sasl.QopIntegrity, nil
			} else {
				return sasl.QopAuthentication, nil
			}
		} else {
			return "", nil
		}
	} else {
		return "", errors.New("GSSAPI authentication not completed")
	}
}

func (p *GssKerbClient) Dispose() {
}

var _ sasl.Client = (*GssKerbClient)(nil)
