package httpsig

import (
	"context"
	"crypto/rand"
	"encoding/base64"
)

// NonceGetter represents a source of random nonces to go into resulting objects.
type NonceGetter interface {
	GetNonce(ctx context.Context) (string, error)
}

type NonceGetterFunc func(ctx context.Context) (string, error)

func (ng NonceGetterFunc) GetNonce(ctx context.Context) (string, error) { return ng(ctx) }

// NonceChecker is responsible for the verification of the nonce received in a signature, e.g. to prevent replay attacks,
// or to verify that the nonce is the expected one, like if requested using the Accept-Signature header.
type NonceChecker interface {
	CheckNonce(ctx context.Context, nonce string) error
}

type NonceCheckerFunc func(ctx context.Context, nonce string) error

func (nc NonceCheckerFunc) GetNonce(ctx context.Context, nonce string) error { return nc(ctx, nonce) }

type noopNonceChecker struct{}

func (n noopNonceChecker) CheckNonce(_ context.Context, _ string) error { return nil }

type nonceGetter struct{}

func (n nonceGetter) GetNonce(_ context.Context) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
