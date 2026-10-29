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

type payloadSigner interface {
	signPayload(data []byte) ([]byte, error)
	algorithm() SignatureAlgorithm
}

func newPayloadSigner(signingKey any, alg SignatureAlgorithm) (payloadSigner, error) {
	switch key := signingKey.(type) {
	case ed25519.PrivateKey:
		return newEd25519Signer(key, alg)
	case *rsa.PrivateKey:
		return newRSASigner(key, alg)
	case *ecdsa.PrivateKey:
		return newECDSASigner(key, alg)
	case []byte:
		return newSymmetricSigner(key, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// Signer creates HTTP message signatures using a configured key, set of
// covered components, and signature parameters.
type Signer interface {
	// Sign signs msg and returns its updated HTTP headers, including the
	// Signature and Signature-Input fields. It also updates msg.Header and
	// may update Content-Digest when that component is covered.
	Sign(msg *Message) (http.Header, error)
}

// SignerOption configures how a Signer constructs HTTP message signatures.
type SignerOption func(s *signer) error

// WithLabel sets the desired Signature-Input and Signature dictionary label.
// The default is "sig". An empty label is ignored; labels may be renamed
// automatically if they collide with an existing signature in the message.
// Labels are not signed and must not be used as identity information.
func WithLabel(label string) SignerOption {
	return func(s *signer) error {
		if len(label) != 0 {
			s.label = label
		}

		return nil
	}
}

// WithTTL sets how long the generated signature remains valid by controlling
// its expires parameter. The default is 30 seconds. A non-positive duration
// omits expires from the generated Signature-Input.
func WithTTL(ttl time.Duration) SignerOption {
	return func(s *signer) error {
		s.ttl = ttl

		return nil
	}
}

// WithComponents selects HTTP fields and derived component identifiers to
// cover with the signature. If "content-digest" is selected, signing also
// generates or updates the Content-Digest field for the message body.
func WithComponents(identifiers ...string) SignerOption {
	return func(s *signer) error {
		var err error

		s.ids, err = toComponentIdentifiers(identifiers)

		return err
	}
}

// WithTag sets the application-defined tag signature parameter. An empty
// tag is ignored, leaving the tag parameter absent.
func WithTag(tag string) SignerOption {
	return func(s *signer) error {
		if len(tag) != 0 {
			s.tag = tag
		}

		return nil
	}
}

// WithNonce sets the source of the nonce signature parameter. By default,
// the signer generates a random nonce. A nil getter leaves that default in
// place; a getter returning an empty string causes nonce to be omitted.
func WithNonce(ng NonceGetter) SignerOption {
	return func(s *signer) error {
		if ng != nil {
			s.ng = ng
		}

		return nil
	}
}

// WithContentDigestAlgorithm selects the algorithm used to generate
// Content-Digest when that component is covered. Without this option, the
// signer generates both supported digests (SHA-256 and SHA-512).
// Unsupported algorithms cause an error during NewSigner.
func WithContentDigestAlgorithm(alg DigestAlgorithm) SignerOption {
	return func(s *signer) error {
		if _, known := supportedAlgs[alg]; !known {
			return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
		}

		s.cdAlg = alg

		return nil
	}
}

// WithKeyID adds the keyid signature parameter with the given key ID.
// An empty value is ignored; no keyid is added unless this option supplies
// a non-empty value.
func WithKeyID(keyID string) SignerOption {
	return func(s *signer) error {
		if len(keyID) != 0 {
			s.keyID = keyID
		}

		return nil
	}
}

// WithAlg includes the alg signature parameter using Key.Algorithm.
// By default, alg is omitted.
func WithAlg() SignerOption {
	return func(s *signer) error {
		s.includeAlg = true

		return nil
	}
}

// NewSigner creates a Signer using key for cryptographic signing. The key
// must contain private or symmetric material compatible with its algorithm.
// By default, the generated signature uses label "sig", includes a created
// timestamp and a random nonce, and expires after 30 seconds.
func NewSigner(key Key, opts ...SignerOption) (Signer, error) {
	ps, err := newPayloadSigner(key.Material, key.Algorithm)
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

	if sig.includeAlg {
		switch sig.ps.algorithm() {
		case RsaPssSha512, RsaPkcs1v15Sha256, HmacSha256, EcdsaP256Sha256, EcdsaP384Sha384, Ed25519:
		default:
			return nil, fmt.Errorf("%w: %s is not registered for HTTP Message Signatures",
				ErrUnsupportedAlgorithm, sig.ps.algorithm())
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
	label      string
	ids        []*componentIdentifier
	ttl        time.Duration
	tag        string
	keyID      string
	includeAlg bool
	ng         NonceGetter
	ps         payloadSigner
	cdAlg      DigestAlgorithm
	mu         messageUpdater
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

	if keyID := s.keyID; keyID != "" {
		params.Add(string(KeyID), keyID)
	}

	if s.includeAlg {
		params.Add(string(Alg), string(s.ps.algorithm()))
	}

	if len(nonce) != 0 {
		params.Add(string(Nonce), nonce)
	}

	if len(s.tag) != 0 {
		params.Add(string(Tag), s.tag)
	}

	return newSignatureInput(s.ids, params), nil
}
