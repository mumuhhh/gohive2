package sasl

type Client interface {
	GetMechanismName() string
	HasInitialResponse() bool
	EvaluateChallenge(challenge []byte) ([]byte, error)
	IsComplete() bool
	Unwrap(incoming []byte) ([]byte, error)
	Wrap(outgoing []byte) ([]byte, error)
	GetNegotiatedProperty(propName string) (string, error)
	Dispose()
}
