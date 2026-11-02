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

type nonceGetter struct{}

func (n nonceGetter) GetNonce(_ context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
