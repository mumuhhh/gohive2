package sasldigest

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"errors"
	"hash"
)

func generatePrivacyKeys(a1 string, cipher string) ([]byte, []byte) {
	sum := h(a1)
	var n int
	switch cipher {
	case "rc4-40":
		n = 5
	case "rc4-56":
		n = 7
	default:
		n = md5.Size
	}

	kcc := md5.Sum(append(sum[:n],
		[]byte("Digest H(A1) to client-to-server sealing key magic constant")...))
	kcs := md5.Sum(append(sum[:n],
		[]byte("Digest H(A1) to server-to-client sealing key magic constant")...))

	return kcc[:], kcs[:]
}

type DigestPrivacy struct {
	sendSeqNum int
	readSeqNum int

	decodeMAC hash.Hash
	encodeMAC hash.Hash

	decryptor *rc4.Cipher
	encryptor *rc4.Cipher
}

func NewDigestPrivacy(kic, kis, kcc, kcs []byte) *DigestPrivacy {
	encryptor, _ := rc4.NewCipher(kcc)
	decryptor, _ := rc4.NewCipher(kcs)

	return &DigestPrivacy{
		encryptor: encryptor,
		decryptor: decryptor,
		decodeMAC: hmac.New(md5.New, kis),
		encodeMAC: hmac.New(md5.New, kic),
	}
}

func (d DigestPrivacy) Wrap(dest []byte) ([]byte, error) {
	inputLen := len(dest)
	if inputLen == 0 {
		return make([]byte, 0), nil
	}
	msg := dest[:]
	seqBuf := lenEncodeBytes(d.sendSeqNum)

	encryptedLen := inputLen + macHMACLen

	mac := msgHMAC(d.encodeMAC, seqBuf, msg)

	cipherBlock := make([]byte, encryptedLen)
	copy(cipherBlock, msg)
	copy(cipherBlock[inputLen:], mac)
	d.encryptor.XORKeyStream(cipherBlock, cipherBlock)
	wrapped := make([]byte, encryptedLen+macMsgTypeLen+macSeqNumLen)
	copy(wrapped, cipherBlock)
	copy(wrapped[encryptedLen:], macMsgType[0:2])
	copy(wrapped[encryptedLen+macMsgTypeLen:], seqBuf[0:4])

	d.sendSeqNum++
	return wrapped, nil
}

func (d DigestPrivacy) Unwrap(outgoing []byte) ([]byte, error) {
	inputLen := len(outgoing)
	if inputLen == 0 {
		return make([]byte, 0), nil
	}
	input := outgoing[:]
	if inputLen < 4 {
		return nil, errors.New("invalid response from datanode: bad response length")
	}

	seqNumStart := inputLen - macSeqNumLen
	msgTypeStart := seqNumStart - macMsgTypeLen

	encryptedLen := inputLen - macMsgTypeLen - macSeqNumLen
	d.decryptor.XORKeyStream(input[:encryptedLen], input[:encryptedLen])

	origHash := input[encryptedLen-macHMACLen : encryptedLen]
	encryptedLen -= macHMACLen

	seqBuf := lenEncodeBytes(d.readSeqNum)
	expectedMac := msgHMAC(d.decodeMAC, seqBuf, input[:encryptedLen])

	msgType := input[msgTypeStart : msgTypeStart+macMsgTypeLen]
	seqNum := input[seqNumStart : seqNumStart+macSeqNumLen]

	if !bytes.Equal(expectedMac, origHash) || !bytes.Equal(macMsgType[:], msgType) || !bytes.Equal(seqNum, seqBuf[:]) {
		return nil, errors.New("invalid response from datanode: HMAC check failed")
	}

	d.readSeqNum++
	return input[:encryptedLen], nil
}

var _ SecurityCtx = (*DigestPrivacy)(nil)
