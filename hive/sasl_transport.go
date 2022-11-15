package hive2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/mumuhhh/gohive2/sasl"
)

const (
	START    byte = 1
	OK       byte = 2
	BAD      byte = 3
	ERROR    byte = 4
	COMPLETE byte = 5
)

type TSaslClientTransport struct {
	tp         thrift.TTransport
	saslClient sasl.Client

	writeBuffer *bytes.Buffer
	readBuffer  *bytes.Buffer
	ctx         context.Context

	shouldWrap bool
}

func NewTSaslClientTransport(tp thrift.TTransport, saslClient sasl.Client) *TSaslClientTransport {
	return &TSaslClientTransport{
		tp:          tp,
		saslClient:  saslClient,
		ctx:         context.Background(),
		writeBuffer: new(bytes.Buffer),
		readBuffer:  new(bytes.Buffer),
	}
}

// ReadFrame reads a frame of data into local buffer, which means first read data's length, then reads actual data.
func (t *TSaslClientTransport) ReadFrame() error {
	header := make([]byte, 4)
	var err error
	if _, err := io.ReadFull(t.tp, header); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint32(header))
	data := make([]byte, length)
	if _, err := io.ReadFull(t.tp, data); err != nil {
		return err
	}
	if t.shouldWrap {
		data, err = t.saslClient.Unwrap(data)
		if err != nil {
			return err
		}
	}
	_, err = t.readBuffer.Write(data)
	return err
}

func (t *TSaslClientTransport) Read(p []byte) (n int, err error) {
	n, err = t.readBuffer.Read(p)
	if n > 0 {
		return n, err
	}
	if err := t.ReadFrame(); err != nil {
		return 0, err
	}
	return t.readBuffer.Read(p)
}

func (t *TSaslClientTransport) Write(p []byte) (n int, err error) {
	return t.writeBuffer.Write(p)
}

func (t *TSaslClientTransport) Close() error {
	return t.tp.Close()
}

func (t *TSaslClientTransport) Flush(ctx context.Context) (err error) {
	buf := t.writeBuffer.Bytes()
	dataLength := t.writeBuffer.Len()
	if t.shouldWrap {
		buf, err = t.saslClient.Wrap(buf)
		if err != nil {
			return err
		}
		dataLength = len(buf)
	}
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(dataLength))

	frame := make([]byte, dataLength+4)
	copy(frame, length[:4])
	copy(frame[4:], buf[:dataLength])
	_, err = t.tp.Write(frame)
	if err == nil {
		t.writeBuffer.Reset()
		return t.tp.Flush(ctx)
	}
	return err
}

func (t *TSaslClientTransport) RemainingBytes() (numBytes uint64) {
	return uint64(t.readBuffer.Len())
}

// sendSaslMessage sends data length, status code and message body
func (t *TSaslClientTransport) sendSaslMessage(status byte, body []byte) (int, error) {
	data := make([]byte, len(body)+5)
	header2 := make([]byte, 4)
	binary.BigEndian.PutUint32(header2, uint32(len(body)))

	data[0] = status
	copy(data[1:], header2)
	copy(data[5:], body)

	n, err := t.tp.Write(data)
	if err != nil {
		return n, err
	}
	if err := t.tp.Flush(t.ctx); err != nil {
		return n, err
	}
	return n, nil
}

// receiveSaslMessage receives init response from server
func (t *TSaslClientTransport) receiveSaslMessage() (byte, []byte, error) {
	header := make([]byte, 5)
	_, err := io.ReadFull(t.tp, header)
	if err != nil {
		return 0, nil, err
	}

	status := header[0]
	payloadBytes := int(binary.BigEndian.Uint32(header[1:]))
	var payload []byte
	if payloadBytes < 0 && payloadBytes > 104857600 {
		message := fmt.Sprintf("Invalid payload header length: %d", payloadBytes)
		_, _ = t.sendSaslMessage(ERROR, []byte(message))
		return 0, nil, errors.New(message)
	} else {
		payload = make([]byte, payloadBytes)
		if _, err := io.ReadFull(t.tp, payload); err != nil {
			return 0, nil, err
		}
	}
	return status, payload, nil
}

func (t *TSaslClientTransport) handleSaslStartMessage() error {
	var initialResponse []byte
	var err error
	if t.saslClient.HasInitialResponse() {
		initialResponse, err = t.saslClient.EvaluateChallenge(initialResponse)
		if err != nil {
			return err
		}
	}

	//LOGGER.debug("Sending mechanism name {} and initial response of length {}", mechanism, initialResponse.length)
	if _, err := t.sendSaslMessage(START, []byte(t.saslClient.GetMechanismName())); err != nil {
		return err
	}
	status := COMPLETE
	if !t.saslClient.IsComplete() {
		status = OK
	}
	// Send initial response
	if _, err := t.sendSaslMessage(status, initialResponse); err != nil {
		return err
	}
	return t.tp.Flush(t.ctx)
}

func (t *TSaslClientTransport) Open() (err error) {

	// opening transport
	if t.saslClient != nil && t.saslClient.IsComplete() {
		return errors.New("SASL transport already open")
	}

	if !t.tp.IsOpen() {
		err = t.tp.Open()
		if err != nil {
			return err
		}
	}
	// Negotiate a SASL mechanism. The client also sends its
	// initial response, or an empty one.
	if err = t.handleSaslStartMessage(); err != nil {
		return err
	}
	// Client: Start message handled
	var msgStatus byte
	var payload []byte
	for !t.saslClient.IsComplete() {
		msgStatus, payload, err = t.receiveSaslMessage()
		if err != nil {
			return err
		}
		if msgStatus != OK && msgStatus != COMPLETE {
			return errors.New("expected COMPLETE or OK")
		}

		if payload, err = t.saslClient.EvaluateChallenge(payload); err != nil {
			return err
		}
		if msgStatus == COMPLETE {
			break
		}
		status := COMPLETE
		if !t.saslClient.IsComplete() {
			status = OK
		}
		if _, err := t.sendSaslMessage(status, payload); err != nil {
			return err
		}
	}
	if msgStatus == OK {
		msgStatus, _, err = t.receiveSaslMessage()
		if err != nil {
			return err
		}
		if msgStatus != COMPLETE {
			return errors.New("expected SASL COMPLETE")
		}
	}
	qop, err := t.saslClient.GetNegotiatedProperty("sasl.qop")
	if err != nil {
		return err
	}
	if qop != "auth" {
		t.shouldWrap = true
	}
	return nil
}

func (t *TSaslClientTransport) IsOpen() bool {
	return t.tp.IsOpen() && t.saslClient != nil && t.saslClient.IsComplete()
}

var _ thrift.TTransport = (*TSaslClientTransport)(nil)
