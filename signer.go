package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/dunglas/httpsfv"
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

func WithContentDigestAlgorithm(alg DigestAlgorithm) SignerOption {
	return func(s *signer) error {
		if _, known := supportedAlgs[alg]; !known {
			return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
		}

		s.cdAlg = alg

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
		mu:    noopMessageUpdater{},
	}

	for _, opt := range opts {
		if err = opt(sig); err != nil {
			return nil, err
		}
	}

	var cmv compositeMessageUpdater

	for _, id := range sig.ids {
		if id.Value == "content-digest" {
			if _, present := id.Params.Get("req"); !present {
				cmv = append(cmv, contentDigester{alg: supportedAlgs[sig.cdAlg], algName: sig.cdAlg})
			}
		}
	}

	if len(cmv) != 0 {
		sig.mu = cmv
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
	cdAlg DigestAlgorithm
	mu    messageUpdater
}

func (s *signer) Sign(msg *Message) (http.Header, error) {
	params, err := s.signatureInput(msg.Context)
	if err != nil {
		return nil, err
	}

	if err = s.mu.update(msg); err != nil {
		return nil, err
	}

	base, err := newSignatureBase(params, msg)
	if err != nil {
		return nil, err
	}

	sb, err := base.marshal()
	if err != nil {
		return nil, err
	}

	signature, err := s.ps.signPayload(sb)
	if err != nil {
		return nil, err
	}

	return msg.addSignature(s.label, signature, params.value)
}

func (s *signer) signatureInput(ctx context.Context) (*signatureInput, error) {
	created := currentTime().UTC()

	nonce, err := s.ng.GetNonce(ctx)
	if err != nil {
		return nil, err
	}

	params := httpsfv.NewParams()
	params.Add(string(Created), created.Unix())

	if s.ttl > 0 {
		params.Add(string(Expires), created.Add(s.ttl).Unix())
	}

	if keyID := s.ps.keyID(); keyID != "" {
		params.Add(string(KeyID), keyID)
	}

	if alg := filterAlgorithm(s.ps.algorithm()); alg != "" {
		params.Add(string(Alg), string(alg))
	}

	if len(nonce) != 0 {
		params.Add(string(Nonce), nonce)
	}

	if len(s.tag) != 0 {
		params.Add(string(Tag), s.tag)
	}

	return newSignatureInput(s.ids, params), nil
}
