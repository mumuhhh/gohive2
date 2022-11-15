package sasldigest

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/rand"
	"strings"

	"github.com/mumuhhh/gohive2/sasl"
)

const (
	macHMACLen    = 10
	macMsgTypeLen = 2
	macSeqNumLen  = 4
)

var macMsgType = [2]byte{0x00, 0x01}

func lenEncodeBytes(seqnum int) (out [4]byte) {
	out[0] = byte((seqnum >> 24) & 0xFF)
	out[1] = byte((seqnum >> 16) & 0xFF)
	out[2] = byte((seqnum >> 8) & 0xFF)
	out[3] = byte(seqnum & 0xFF)
	return
}

type SecurityCtx interface {
	Wrap(dest []byte) ([]byte, error)
	Unwrap(outgoing []byte) ([]byte, error)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func generateNonce(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func h(s string) []byte {
	hash := md5.Sum([]byte(s))
	return hash[:]
}

func NewDigestMD5Client(authzid, username, password, protocol, serverName string) *DigestMD5Client {
	return &DigestMD5Client{
		authzid:    authzid,
		username:   username,
		password:   password,
		protocol:   protocol,
		serverName: serverName,
	}
}

type DigestMD5Client struct {
	authzid    string
	username   string
	password   string
	protocol   string
	serverName string

	Token *sasl.Challenge

	completed bool
	cnonce    string
	cipher    string
	secCtx    SecurityCtx
}

func (m *DigestMD5Client) GetMechanismName() string {
	return "DIGEST-MD5"
}

func (m *DigestMD5Client) HasInitialResponse() bool {
	return false
}

func (m *DigestMD5Client) a1() string {
	x := h(strings.Join([]string{m.username, m.Token.Realm, m.password}, ":"))
	y := []string{string(x), m.Token.Nonce, m.cnonce}
	if m.authzid != "" {
		y = append(y, m.authzid)
	}
	return strings.Join(y, ":")
}

func (m *DigestMD5Client) a2(initial bool) string {
	digestURI := m.protocol + "/" + m.serverName
	var a2 []string
	if initial {
		a2 = append(a2, "AUTHENTICATE")
	} else {
		a2 = append(a2, "")
	}
	a2 = append(a2, digestURI)
	if m.Token.Qop[0] == sasl.QopPrivacy || m.Token.Qop[0] == sasl.QopIntegrity {
		a2 = append(a2, "00000000000000000000000000000000")
	}
	return strings.Join(a2, ":")
}

func kd(k, s string) []byte {
	return h(k + ":" + s)
}

func (m *DigestMD5Client) compute(initial bool) string {
	x := hex.EncodeToString(h(m.a1()))
	y := strings.Join([]string{
		m.Token.Nonce,
		fmt.Sprintf("%08x", 1),
		m.cnonce,
		m.Token.Qop[0],
		hex.EncodeToString(h(m.a2(initial))),
	}, ":")
	return hex.EncodeToString(kd(x, y))
}

func chooseCipher(options []string) string {
	s := make(map[string]bool)
	for _, c := range options {
		s[c] = true
	}

	switch {
	case s["rc4"]:
		return "rc4"
	case s["rc4-56"]:
		return "rc4-56"
	case s["rc4-40"]:
		return "rc4-40"
	default:
		return ""
	}
}

func (m *DigestMD5Client) challengeStep1(challenge []byte) ([]byte, error) {
	var err error
	m.Token, err = sasl.ParseChallenge(challenge)
	if err != nil {
		return nil, err
	}

	m.cnonce = generateNonce(16)
	if err != nil {
		return nil, err
	}

	m.cipher = chooseCipher(m.Token.Cipher)
	rspdigest := m.compute(true)

	ret := fmt.Sprintf(`username="%s", realm="%s", nonce="%s", cnonce="%s", nc=%08x, qop=%s, digest-uri="%s/%s", response=%s, charset=utf-8`,
		m.username, m.Token.Realm, m.Token.Nonce, m.cnonce, 1, m.Token.Qop[0], m.protocol, m.serverName, rspdigest)

	if m.cipher != "" {
		ret += ", cipher=" + m.cipher
	}

	return []byte(ret), nil
}

// challengeStep2 implements step two of RFC 2831.
func (m *DigestMD5Client) challengeStep2(challenge []byte) error {
	rspauth := strings.Split(string(challenge), "=")

	if rspauth[0] != "rspauth" {
		return fmt.Errorf("rspauth not in '%s'", string(challenge))
	}

	if rspauth[1] != m.compute(false) {
		return errors.New("rspauth did not match digest")
	}

	if m.Token.Qop[0] == sasl.QopPrivacy || m.Token.Qop[0] == sasl.QopIntegrity {
		kic, kis := generateIntegrityKeys(m.a1())
		if m.Token.Qop[0] == sasl.QopPrivacy {
			kcc, kcs := generatePrivacyKeys(m.a1(), m.cipher)
			m.secCtx = NewDigestPrivacy(kic, kis, kcc, kcs)
		} else {
			m.secCtx = NewDigestIntegrity(kic, kis)
		}
	}

	return nil
}

func (m *DigestMD5Client) EvaluateChallenge(challenge []byte) ([]byte, error) {
	length := len(challenge)
	if length > 2048 {
		return nil, errors.New(fmt.Sprintf("DIGEST-MD5: Invalid digest-challenge length. Got: %d  Expected < 2048", length))
	}
	if strings.HasPrefix(string(challenge), "rspauth") {
		err := m.challengeStep2(challenge)
		m.completed = true
		return nil, err
	}
	return m.challengeStep1(challenge)
}

func (m *DigestMD5Client) IsComplete() bool {
	return m.completed
}

func (m *DigestMD5Client) Unwrap(incoming []byte) ([]byte, error) {
	if !m.completed {
		return nil, errors.New("DIGEST-MD5 authentication not completed")
	}
	if m.secCtx == nil {
		return nil, errors.New("neither integrity nor privacy was negotiated")
	}
	return m.secCtx.Unwrap(incoming)
}

func (m *DigestMD5Client) Wrap(outgoing []byte) ([]byte, error) {
	if !m.completed {
		return nil, errors.New("DIGEST-MD5 authentication not completed")
	}
	if m.secCtx == nil {
		return nil, errors.New("neither integrity nor privacy was negotiated")
	}
	return m.secCtx.Wrap(outgoing)
}

func (m *DigestMD5Client) GetNegotiatedProperty(propName string) (string, error) {
	if m.completed {
		if propName == "sasl.bound.server.name" {
			return m.serverName, nil
		} else if propName == "sasl.qop" {
			return m.Token.Qop[0], nil
		} else if propName == "sasl.maxbuffer" {
			return "65536", nil
		} else if propName == "sasl.sendmaxbuffer" {
			return "0", nil
		} else {
			return "", nil
		}
	} else {
		return "", errors.New("DIGEST-MD5 authentication not completed")
	}
}

func (m *DigestMD5Client) Dispose() {
	m.secCtx = nil
}

// msgHMAC implements the HMAC wrapper per the RFC:
//
//	HMAC(ki, {seqnum, msg})[0..9].
func msgHMAC(mac hash.Hash, seq [4]byte, msg []byte) []byte {
	mac.Reset()
	mac.Write(seq[:])
	mac.Write(msg)

	return mac.Sum(nil)[:10]
}

var _ sasl.Client = (*DigestMD5Client)(nil)
