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
	sign(ctx context.Context, data []byte) ([]byte, error)
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
	// Options apply only to this invocation and do not modify the Signer.
	Sign(msg *Message, opts ...SignOption) (http.Header, error)
}

// NewSigner creates a Signer using key for cryptographic signing. The key
// must contain private or symmetric material compatible with its algorithm.
// By default, signatures use label "sig", include created, and expire
// after 30 seconds. The alg, keyid, tag, and nonce parameters are omitted.
// When generating Content-Digest, the signer uses both SHA-256 and SHA-512
// unless WithContentDigestAlgorithm selects one.
//
//nolint:cyclop
func NewSigner(key Key, opts ...SignerOption) (Signer, error) {
	ps, err := newPayloadSigner(key.Material, key.Algorithm)
	if err != nil {
		return nil, err
	}

	sig := &signer{
		label:  "sig",
		ttl:    30 * time.Second, //nolint:mnd
		ps:     ps,
		mu:     noopMessageUpdater{},
		sigAlg: key.Algorithm,
	}

	for _, opt := range opts {
		if err = opt.applySignerOption(sig); err != nil {
			return nil, err
		}
	}

	if sig.includeAlg {
		switch key.Algorithm {
		case RsaPssSha512, RsaPkcs1v15Sha256, HmacSha256, EcdsaP256Sha256, EcdsaP384Sha384, Ed25519:
		default:
			return nil, fmt.Errorf("%w: %s is not registered for HTTP Message Signatures",
				ErrUnsupportedAlgorithm, key.Algorithm)
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

	// Covered components are fixed for the lifetime of this Signer.
	// Prepare their Structured-Fields identifiers once for the signature base.
	sig.serializedIdentifiers = make([]string, len(sig.ids))
	for i, id := range sig.ids {
		sig.serializedIdentifiers[i], err = httpsfv.Marshal(id.Item)
		if err != nil {
			return nil, err
		}
	}

	return sig, nil
}

type signer struct {
	label                 string
	ids                   []*componentIdentifier
	serializedIdentifiers []string
	ttl                   time.Duration
	tag                   string
	keyID                 string
	includeAlg            bool
	ps                    payloadSigner
	sigAlg                SignatureAlgorithm
	cdAlg                 DigestAlgorithm
	parameters            []parameterOption
	mu                    messageUpdater
}

func (s *signer) Sign(msg *Message, opts ...SignOption) (http.Header, error) {
	callOptions := signOptions{staticParameters: s.parameters}
	for _, opt := range opts {
		if err := opt.applySignOption(&callOptions); err != nil {
			return nil, err
		}
	}

	params := s.signatureInput(callOptions)

	if err := s.mu.update(msg); err != nil {
		return nil, err
	}

	base, err := newSignatureBase(msg, params, s.serializedIdentifiers)
	if err != nil {
		return nil, err
	}

	signature, err := s.ps.sign(msg.Context, base.marshal())
	if err != nil {
		return nil, err
	}

	label := s.label
	if callOptions.label != "" {
		label = callOptions.label
	}

	return msg.addSignature(label, signature, params.value)
}

func (s *signer) signatureInput(opts signOptions) *signatureInput {
	created := currentTime().UTC()

	params := httpsfv.NewParams()
	params.Add(string(Created), created.Unix())

	if s.ttl > 0 {
		params.Add(string(Expires), created.Add(s.ttl).Unix())
	}

	if keyID := s.keyID; keyID != "" {
		params.Add(string(KeyID), keyID)
	}

	if s.includeAlg {
		params.Add(string(Alg), string(s.sigAlg))
	}

	if opts.nonceSet {
		params.Add(string(Nonce), opts.nonce)
	}

	if len(s.tag) != 0 {
		params.Add(string(Tag), s.tag)
	}

	for _, param := range s.parameters {
		params.Add(param.name, param.value)
	}

	for _, param := range opts.parameters {
		params.Add(param.name, param.value)
	}

	return newSignatureInput(s.ids, params)
}
