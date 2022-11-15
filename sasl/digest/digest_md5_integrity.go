package sasldigest

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"hash"
)

func generateIntegrityKeys(a1 string) ([]byte, []byte) {
	clientIntMagicStr := []byte("Digest session key to client-to-server signing key magic constant")
	serverIntMagicStr := []byte("Digest session key to server-to-client signing key magic constant")

	sum := h(a1)
	kic := md5.Sum(append(sum[:], clientIntMagicStr...))
	kis := md5.Sum(append(sum[:], serverIntMagicStr...))

	return kic[:], kis[:]
}

type DigestIntegrity struct {
	sendSeqNum int
	readSeqNum int

	encodeMAC hash.Hash
	decodeMAC hash.Hash
}

func NewDigestIntegrity(kic, kis []byte) *DigestIntegrity {
	return &DigestIntegrity{
		encodeMAC: hmac.New(md5.New, kic),
		decodeMAC: hmac.New(md5.New, kis),
	}
}

func (d *DigestIntegrity) Wrap(dest []byte) ([]byte, error) {
	inputLen := len(dest)
	if inputLen == 0 {
		return make([]byte, 0), nil
	}
	msg := dest[:]
	seqBuf := lenEncodeBytes(d.sendSeqNum)
	wrapped := make([]byte, inputLen+macHMACLen+macMsgTypeLen+macSeqNumLen)
	copy(wrapped, msg)
	mac := msgHMAC(d.encodeMAC, seqBuf, msg)
	copy(wrapped[inputLen:], mac)
	copy(wrapped[inputLen+macHMACLen:], macMsgType[0:2])
	copy(wrapped[inputLen+macHMACLen+macMsgTypeLen:], seqBuf[0:4])
	d.sendSeqNum++
	return wrapped, nil
}

func (d *DigestIntegrity) Unwrap(outgoing []byte) ([]byte, error) {
	inputLen := len(outgoing)
	if inputLen == 0 {
		return make([]byte, 0), nil
	}
	input := outgoing[:]
	// shave off last 16 bytes of message
	seqBuf := lenEncodeBytes(d.readSeqNum)

	dataLen := inputLen - macHMACLen - macMsgTypeLen - macSeqNumLen
	expectedMac := msgHMAC(d.decodeMAC, seqBuf, input[:dataLen])

	seqNumStart := inputLen - 2
	msgTypeStart := seqNumStart - 4
	origHashStart := msgTypeStart - 10

	if !bytes.Equal(expectedMac, input[origHashStart:origHashStart+macHMACLen]) ||
		!bytes.Equal(macMsgType[:], input[msgTypeStart:msgTypeStart+macMsgTypeLen]) ||
		!bytes.Equal(seqBuf[:], input[seqNumStart:seqNumStart+macSeqNumLen]) {
		return nil, errors.New("HMAC Integrity Check failed")
	}

	d.readSeqNum++
	return input[:dataLen], nil
}

var _ SecurityCtx = (*DigestIntegrity)(nil)
