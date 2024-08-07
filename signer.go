package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"net/http"
	"time"
)

type Signer interface {
	Sign(msg *Message) (http.Header, error)
}

type payloadSigner interface {
	signPayload(data []byte) ([]byte, error)
	algorithm() SignatureAlgorithm
	keyID() string
}

func newPayloadSigner(signingKey any, keyID string, alg SignatureAlgorithm) (payloadSigner, error) {
	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		return newEd25519Signer(key, keyID, alg)
	case *rsa.PrivateKey:
		return newRSASigner(key, keyID, alg)
	case *ecdsa.PrivateKey:
		return newECDSASigner(key, keyID, alg)
	case []byte:
		return newSymmetricSigner(key, keyID, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

type SignerOption func(s *signer) error

// WithLabel sets the label of the signature in the Signature-Input and Signature headers.
func WithLabel(label string) SignerOption {
	return func(s *signer) error {
		if len(label) != 0 {
			s.label = label
		}

		return nil
	}
}

func WithTTL(ttl time.Duration) SignerOption {
	return func(s *signer) error {
		s.ttl = ttl

		return nil
	}
}

// WithComponents sets the HTTP fields / derived component names to be included in signing.
func WithComponents(identifiers ...string) SignerOption {
	return func(s *signer) error {
		var err error
		s.ids, err = toComponentIdentifiers(identifiers)

		return err
	}
}

func WithTag(tag string) SignerOption {
	return func(s *signer) error {
		if len(tag) != 0 {
			s.tag = tag
		}

		return nil
	}
}

func WithNonce(ng NonceGetter) SignerOption {
	return func(s *signer) error {
		if ng != nil {
			s.ng = ng
		}

		return nil
	}
}

// NewSigner creates a new signer with the given options.
func NewSigner(key Key, opts ...SignerOption) (Signer, error) {
	ps, err := newPayloadSigner(key.Key, key.KeyID, key.Algorithm)
	if err != nil {
		return nil, err
	}

	sig := &signer{
		label: "sig",
		ttl:   30 * time.Second, //nolint:mnd
		ng:    nonceGetter{},
		ps:    ps,
	}

	for _, opt := range opts {
		if err = opt(sig); err != nil {
			return nil, err
		}
	}

	return sig, nil
}

type signer struct {
	label string
	ids   []*componentIdentifier
	ttl   time.Duration
	tag   string
	ng    NonceGetter
	ps    payloadSigner
}

func (s *signer) Sign(msg *Message) (http.Header, error) {
	sp, err := s.signatureParameters(msg.Context)
	if err != nil {
		return nil, err
	}

	base, err := sp.toSignatureBase(msg)
	if err != nil {
		return nil, err
	}

	signature, err := s.ps.signPayload(base)
	if err != nil {
		return nil, err
	}

	return msg.addSignature(s.label, signature, sp.InnerList)
}

func (s *signer) signatureParameters(ctx context.Context) (*signatureParameters, error) {
	var (
		created time.Time
		expires time.Time
		nonce   string
		err     error
	)

	created = currentTime().UTC()
	if s.ttl > 0 {
		expires = created.Add(s.ttl)
	}

	nonce, err = s.ng.GetNonce(ctx)
	if err != nil {
		return nil, err
	}

	return newSignatureParameters(
		created,
		expires,
		nonce,
		s.ps.keyID(),
		s.tag,
		filterAlgorithm(s.ps.algorithm()),
		s.ids,
	), nil
}
