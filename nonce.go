package httpsig

import (
	"context"
	"crypto/rand"
	"encoding/base64"
)

// NonceGetter supplies a nonce for a newly generated signature or an
// Accept-Signature negotiation request. An empty result omits the parameter;
// implementations are responsible for producing appropriate nonce values.
type NonceGetter interface {
	// GetNonce returns a nonce or an error for the given context.
	GetNonce(ctx context.Context) (string, error)
}

// NonceGetterFunc adapts a function to the NonceGetter interface.
type NonceGetterFunc func(ctx context.Context) (string, error)

// GetNonce calls the wrapped nonce-generating function.
func (ng NonceGetterFunc) GetNonce(ctx context.Context) (string, error) { return ng(ctx) }

// NonceChecker checks the nonce parameter of a signature, for example to
// enforce replay protection or correlate a negotiated signature. It receives
// both the value and whether the parameter was present. CheckNonce is called
// before the cryptographic signature check; implementations that update replay
// state must account for unsuccessful verification attempts.
type NonceChecker interface {
	// CheckNonce returns an error if the nonce must be rejected.
	CheckNonce(ctx context.Context, nonce NonceValue) error
}

// NonceValue represents the received nonce parameter and its presence.
// A missing nonce and an explicitly empty nonce are different values.
type NonceValue struct {
	// Present is true when the signature explicitly contains nonce.
	Present bool
	// Value is the transmitted nonce value, or empty when absent.
	Value string
}

// NonceCheckerFunc adapts a function to the NonceChecker interface.
type NonceCheckerFunc func(ctx context.Context, nonce NonceValue) error

// CheckNonce calls the wrapped nonce-checking function.
func (f NonceCheckerFunc) CheckNonce(ctx context.Context, nonce NonceValue) error {
	return f(ctx, nonce)
}

type noopNonceChecker struct{}

func (n noopNonceChecker) CheckNonce(_ context.Context, _ NonceValue) error { return nil }

type nonceGetter struct{}

func (n nonceGetter) GetNonce(_ context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
