package saslcrammd5

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"github.com/mumuhhh/gohive2/sasl"
)

type CramMD5Client struct {
	completed bool
	username  string
	password  string
}

func NewCramMD5Client(username, password string) *CramMD5Client {
	return &CramMD5Client{
		username: username,
		password: password,
	}
}

func (p *CramMD5Client) GetMechanismName() string {
	return "CRAM-MD5"
}

func (p *CramMD5Client) HasInitialResponse() bool {
	return false
}

func (p *CramMD5Client) EvaluateChallenge(challenge []byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("CRAM-MD5 authentication already completed")
	}
	digest := HmacMD5([]byte(p.password), challenge)
	p.completed = true
	return []byte(p.username + " " + digest), nil
}

func (p *CramMD5Client) IsComplete() bool {
	return p.completed
}

func (p *CramMD5Client) Unwrap([]byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("CRAM-MD5 supports neither integrity nor privacy")
	}
	return nil, errors.New("CRAM-MD5 authentication not completed")
}

func (p *CramMD5Client) Wrap([]byte) ([]byte, error) {
	if p.completed {
		return nil, errors.New("CRAM-MD5 supports neither integrity nor privacy")
	}
	return nil, errors.New("CRAM-MD5 authentication not completed")
}

func (p *CramMD5Client) GetNegotiatedProperty(propName string) (string, error) {
	if p.completed {
		if propName == "sasl.qop" {
			return sasl.QopAuthentication, nil
		} else {
			return "", nil
		}
	} else {
		return "", errors.New("CRAM-MD5 authentication not completed")
	}
}

func (p *CramMD5Client) Dispose() {
	p.password = ""
}

var _ sasl.Client = (*CramMD5Client)(nil)

func HmacMD5(key, text []byte) string {
	var keyLocal = key

	if len(keyLocal) > 64 {
		bytes := md5.Sum(key)
		keyLocal = bytes[:]
	}
	/* digest the key if longer than 64 bytes */
	ipad := make([]byte, 64) /* inner padding */
	opad := make([]byte, 64) /* outer padding */
	var digest []byte

	/* store key in pads */
	for i := 0; i < len(keyLocal); i++ {
		ipad[i] = key[i]
		opad[i] = key[i]
	}

	/* XOR key with pads */
	for i := 0; i < 64; i++ {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	/* inner MD5 */
	hash := md5.New()
	hash.Write(ipad)
	hash.Write(text)
	digest = hash.Sum([]byte{})

	/* outer MD5 */
	hash = md5.New()
	hash.Write(opad)
	hash.Write(digest)
	digest = hash.Sum([]byte{})

	// Get character representation of digest
	return hex.EncodeToString(digest)
}
