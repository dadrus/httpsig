package httpsig

import "context"

// NonceGetter supplies a nonce for an Accept-Signature request. An empty
// result omits the nonce parameter. Generating and correlating nonce values
// is the responsibility of the calling application.
type NonceGetter interface {
	// GetNonce returns a nonce or an error for the given context.
	GetNonce(ctx context.Context) (string, error)
}

// NonceGetterFunc adapts a function to the NonceGetter interface.
type NonceGetterFunc func(ctx context.Context) (string, error)

// GetNonce calls the wrapped function.
func (ng NonceGetterFunc) GetNonce(ctx context.Context) (string, error) { return ng(ctx) }
