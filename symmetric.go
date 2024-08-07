package httpsig

import (
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
	"fmt"
)

func newSymmetricSigner(key []byte, kid string, alg SignatureAlgorithm) (*symmetricSigner, error) {
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
		alg:  alg,
		key:  key,
		kid:  kid,
		hash: hash,
	}, nil
}

type symmetricSigner struct {
	alg  SignatureAlgorithm
	key  []byte
	kid  string
	hash crypto.Hash
}

func (ms *symmetricSigner) keyID() string { return ms.kid }

func (ms *symmetricSigner) algorithm() SignatureAlgorithm { return ms.alg }

func (ms *symmetricSigner) signPayload(data []byte) ([]byte, error) { return ms.hmac(data), nil }

func (ms *symmetricSigner) verifyPayload(data []byte, mac []byte) error {
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
