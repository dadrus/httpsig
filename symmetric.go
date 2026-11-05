package httpsig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
)

func newSymmetricSigner(key []byte, alg SignatureAlgorithm) (*symmetricSigner, error) {
	var hash crypto.Hash

	switch alg {
	case HmacSha256:
		hash = crypto.SHA256
	case HmacSha384:
		hash = crypto.SHA384
	case HmacSha512:
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	return &symmetricSigner{
		key:  bytes.Clone(key),
		hash: hash,
	}, nil
}

type symmetricSigner struct {
	key  []byte
	hash crypto.Hash
}

func (ms *symmetricSigner) sign(_ context.Context, data []byte) ([]byte, error) {
	return ms.hmac(data), nil
}

func (ms *symmetricSigner) verify(_ context.Context, data []byte, mac []byte) error {
	if match := subtle.ConstantTimeCompare(mac, ms.hmac(data)); match != 1 {
		return ErrInvalidSignature
	}

	return nil
}

func (ms *symmetricSigner) hmac(payload []byte) []byte {
	hmac := hmac.New(ms.hash.New, ms.key)

	// According to documentation, Write() on hash never fails
	_, _ = hmac.Write(payload)
	mac := hmac.Sum(nil)

	return mac
}
