package httpsig

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dunglas/httpsfv"
)

type signOptions struct {
	label            string
	nonce            string
	nonceSet         bool
	staticParameters []parameterOption
	parameters       []parameterOption
}

type sigNegotiationOptions struct {
	opts []AcceptSignatureOption
}

// SignerOption configures how a Signer constructs HTTP message signatures.
type SignerOption interface {
	applySignerOption(s *signer) error
}

// SignOption configures a single Sign call.
type SignOption interface {
	applySignOption(opts *signOptions) error
}

// SignatureNegotiationOption configures the additional values requested by
// WithSignatureNegotiation beyond the verifier's existing requirements.
type SignatureNegotiationOption interface {
	applySignatureNegotiationOption(opts *sigNegotiationOptions)
}

// VerifierOption configures which signatures to verify and which generic
// checks to apply. Options can be provided to NewVerifier or used within
// WithRequiredTag for per-tag expectations.
type VerifierOption interface {
	applyVerifierOption(v *verifier, e *expectations, inTag bool) error
}

// AcceptSignatureOption configures the Accept-Signature request produced by
// NewAcceptSignature and AcceptSignatureBuilder.Build.
type AcceptSignatureOption interface {
	applyAcceptSignatureOption(builder *AcceptSignatureBuilder) error
}

type signerOptionFunc func(*signer) error

func (f signerOptionFunc) applySignerOption(s *signer) error {
	return f(s)
}

type signatureNegotiationOptionFunc func(*sigNegotiationOptions)

func (f signatureNegotiationOptionFunc) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	f(opts)
}

type verifierOptionFunc func(*verifier, *expectations, bool) error

func (f verifierOptionFunc) applyVerifierOption(v *verifier, e *expectations, inTag bool) error {
	return f(v, e, inTag)
}

type acceptSignatureOptionFunc func(*AcceptSignatureBuilder) error

func (f acceptSignatureOptionFunc) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	return f(asb)
}

// WithLabel configures the technical signature label.
// NOTE: Labels are not signed and may be renamed if they collide with existing
// signature labels in a message.
func WithLabel(label string) labelOption {
	return labelOption(label)
}

type labelOption string

func (o labelOption) applySignerOption(s *signer) error {
	if len(o) != 0 {
		s.label = string(o)
	}

	return nil
}

func (o labelOption) applySignOption(opts *signOptions) error {
	if len(o) != 0 {
		opts.label = string(o)
	}

	return nil
}

func (o labelOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	if len(o) != 0 {
		asb.label = string(o)
	}

	return nil
}

func (o labelOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

// WithTTL sets how long the generated signature remains valid by controlling
// its expires parameter. A non-positive duration omits expires from the
// generated Signature-Input.
func WithTTL(ttl time.Duration) SignerOption {
	return signerOptionFunc(func(s *signer) error {
		s.ttl = ttl

		return nil
	})
}

// WithComponents configures HTTP fields and derived component identifiers.
// NewSigner signs these components, NewVerifier requires them to be covered,
// and NewAcceptSignature requests their coverage from the peer.
// If the signer covers its own "content-digest" field, it also generates or
// updates that field from the message body.
func WithComponents(identifiers ...string) componentsOption {
	return componentsOption{identifiers: identifiers}
}

type componentsOption struct {
	identifiers []string
}

func (o componentsOption) applySignerOption(s *signer) error {
	var err error

	s.ids, err = toComponentIdentifiers(o.identifiers)

	return err
}

func (o componentsOption) applyVerifierOption(_ *verifier, exp *expectations, _ bool) error {
	var err error

	exp.identifiers, err = toComponentIdentifiers(o.identifiers)

	return err
}

func (o componentsOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	ids, err := toComponentIdentifiers(o.identifiers)
	if err != nil {
		return err
	}

	asb.setIdentifiers(ids)

	return nil
}

// WithTag configures the application-defined tag signature parameter.
func WithTag(tag string) tagOption {
	return tagOption(tag)
}

type tagOption string

func (o tagOption) applySignerOption(s *signer) error {
	if len(o) != 0 {
		s.tag = string(o)
	}

	return nil
}

func (o tagOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.tag = string(o)

	return nil
}

// WithNonce configures the source for the nonce signature parameter.
// A nil getter leaves the configured source unchanged. If the getter returns
// an empty string, the nonce parameter is omitted.
func WithNonce(ng NonceGetter) SignerOption {
	return signerOptionFunc(func(s *signer) error {
		if ng != nil {
			s.ng = ng
		}

		return nil
	})
}

// WithContentDigestAlgorithm selects the algorithm used to generate
// Content-Digest when that component is covered. Unsupported algorithms
// cause an error.
func WithContentDigestAlgorithm(alg DigestAlgorithm) SignerOption {
	return signerOptionFunc(func(s *signer) error {
		if _, known := supportedAlgs[alg]; !known {
			return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
		}

		s.cdAlg = alg

		return nil
	})
}

// WithKeyID configures the keyid signature parameter. An empty value is
// ignored by the Signer and omitted from an Accept-Signature request.
func WithKeyID(keyID string) keyIDOption {
	return keyIDOption(keyID)
}

type keyIDOption string

func (o keyIDOption) applySignerOption(s *signer) error {
	if len(o) != 0 {
		s.keyID = string(o)
	}

	return nil
}

func (o keyIDOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.keyID = string(o)

	return nil
}

func (o keyIDOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

// WithAlg includes the alg signature parameter of the given Key.
func WithAlg() SignerOption {
	return signerOptionFunc(func(s *signer) error {
		s.includeAlg = true

		return nil
	})
}

// WithParameter adds a static or per-call signature parameter to Signature-Input.
// Extension values may be string, Token, bool, int, int64, float64, or []byte.
// Standard RFC 9421 parameter names are reserved, except that Sign permits
// "nonce" as a non-empty string, overriding the configured nonce source for
// that call. Duplicate parameter names are rejected.
func WithParameter(name string, value any) parameterOption {
	return parameterOption{name: name, value: value}
}

type parameterOption struct {
	name  string
	value any
}

func (o parameterOption) applySignerOption(s *signer) error {
	return addParameter(&s.parameters, nil, o, true)
}

func (o parameterOption) applySignOption(opts *signOptions) error {
	if o.name == string(Nonce) {
		if opts.nonceSet {
			return fmt.Errorf("%w: duplicate signature parameter %q", ErrParameter, o.name)
		}
		nonce, ok := o.value.(string)
		if !ok || nonce == "" {
			return fmt.Errorf("%w: nonce must be a non-empty string", ErrParameter)
		}
		if err := validateParameter(o.name, nonce); err != nil {
			return err
		}
		opts.nonce = nonce
		opts.nonceSet = true

		return nil
	}

	return addParameter(&opts.parameters, opts.staticParameters, o, false)
}

// WithValidityTolerance allows a clock skew of d when checking the created
// and expires signature parameters.
func WithValidityTolerance(d time.Duration) VerifierOption {
	return verifierOptionFunc(func(_ *verifier, e *expectations, _ bool) error {
		e.tolerance = d

		return nil
	})
}

// WithMaxAge sets the maximum age of signatures with a created timestamp.
func WithMaxAge(d time.Duration) VerifierOption {
	return verifierOptionFunc(func(_ *verifier, e *expectations, _ bool) error {
		e.maxAge = d

		return nil
	})
}

// WithNonceChecker sets the checker for the nonce parameter, including when
// the parameter is absent.
func WithNonceChecker(checker NonceChecker) VerifierOption {
	// TODO: Maybe we should use checker after cryptographic verification has succeeded
	return verifierOptionFunc(func(v *verifier, _ *expectations, _ bool) error {
		if checker != nil {
			v.nonceChecker = checker
		}

		return nil
	})
}

// WithRequiredTag selects signatures with the given application tag and
// applies opts to that signature. Each tag may be configured only once.
// An empty tag is not allowed.
func WithRequiredTag(tag string, opts ...VerifierOption) VerifierOption {
	return verifierOptionFunc(func(ver *verifier, _ *expectations, f bool) error {
		if f {
			panic("WithRequiredTag cannot be used as option for itself")
		}

		if len(tag) == 0 {
			return fmt.Errorf("%w: required tag must not be empty", ErrParameter)
		}

		if _, configured := ver.tagExpectations[tag]; configured {
			return fmt.Errorf("%w: requirements for tag %s are already configured", ErrParameter, tag)
		}

		exp := &expectations{
			tolerance: -1,
			maxAge:    -1,
		}

		for _, opt := range opts {
			if err := opt.applyVerifierOption(ver, exp, true); err != nil {
				return err
			}
		}

		ver.tagExpectations[tag] = exp

		return nil
	})
}

// WithValidateAllSignatures verifies every signature in the message. When a
// signature has a configured tag, its per-tag requirements apply; otherwise,
// global requirements apply.
func WithValidateAllSignatures() VerifierOption {
	return verifierOptionFunc(func(v *verifier, _ *expectations, _ bool) error {
		v.validateAllSigs = true

		return nil
	})
}

// WithCreatedTimestamp specifies whether created must be present during
// verification or requested in Accept-Signature. If false, a present created
// timestamp is still validated during verification.
func WithCreatedTimestamp(flag bool) createdTimestampOption {
	return createdTimestampOption(flag)
}

type createdTimestampOption bool

func (o createdTimestampOption) applyVerifierOption(_ *verifier, exp *expectations, _ bool) error {
	flag := bool(o)
	exp.reqCreatedTS = &flag

	return nil
}

func (o createdTimestampOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.addCreatedTS = bool(o)

	return nil
}

// WithExpiredTimestamp specifies whether expires must be present during
// verification or requested in Accept-Signature. If false, a present expires
// timestamp is still validated during verification.
func WithExpiredTimestamp(flag bool) expiredTimestampOption {
	return expiredTimestampOption(flag)
}

type expiredTimestampOption bool

func (o expiredTimestampOption) applyVerifierOption(_ *verifier, exp *expectations, _ bool) error {
	flag := bool(o)
	exp.reqExpiresTS = &flag

	return nil
}

func (o expiredTimestampOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.addExpiresTS = bool(o)

	return nil
}

// WithSignatureNegotiation enables Accept-Signature negotiation when a
// required signature or required component or parameter is missing.
//
// Negotiation reuses the relevant verifier requirements; opts specify only
// additional requests such as a key ID, nonce, algorithm, or label.
func WithSignatureNegotiation(opts ...SignatureNegotiationOption) VerifierOption {
	no := &sigNegotiationOptions{opts: make([]AcceptSignatureOption, 0, len(opts))}
	for _, opt := range opts {
		opt.applySignatureNegotiationOption(no)
	}

	return verifierOptionFunc(func(_ *verifier, exp *expectations, _ bool) error {
		builder, err := NewAcceptSignature(no.opts...)
		if err != nil {
			return err
		}

		exp.asb = builder

		return nil
	})
}

// WithRequestedNonce supplies the nonce source for Accept-Signature
// negotiation.
func WithRequestedNonce(ng NonceGetter) SignatureNegotiationOption {
	return signatureNegotiationOptionFunc(func(sno *sigNegotiationOptions) {
		sno.opts = append(sno.opts, WithExpectedNonce(ng))
	})
}

// WithSignatureAlgorithm requests an alg value from the peer.
func WithSignatureAlgorithm(alg SignatureAlgorithm) signatureAlgorithmOption {
	return signatureAlgorithmOption(alg)
}

type signatureAlgorithmOption SignatureAlgorithm

func (o signatureAlgorithmOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.signatureAlgorithm = SignatureAlgorithm(o)

	return nil
}

func (o signatureAlgorithmOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

// WithExpectedNonce configures the nonce source for Accept-Signature.
// A nil getter leaves the configured source unchanged.
func WithExpectedNonce(ng NonceGetter) AcceptSignatureOption {
	// TODO: What can we do for profiles which make use of nonces but in a different parameter
	return acceptSignatureOptionFunc(func(asb *AcceptSignatureBuilder) error {
		if ng != nil {
			asb.nonceGetter = ng
		}

		return nil
	})
}

// WithContentDigestAlgorithmPreferences sets the Want-Content-Digest
// preferences for NewAcceptSignature or WithSignatureNegotiation when the
// requested components contain content-digest.
func WithContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) contentDigestAlgorithmPreferencesOption {
	return prefs
}

type contentDigestAlgorithmPreferencesOption []AlgorithmPreference

func (o contentDigestAlgorithmPreferencesOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	if len(o) == 0 {
		return nil
	}

	algPrefs := make([]string, len(o))

	for i, pref := range o {
		if pref.Algorithm == "" {
			return fmt.Errorf("%w: digest algorithm preference requires a non-empty algorithm", ErrParameter)
		}

		algPrefs[i] = pref.String()
	}

	asb.cdAlgPrefs = algPrefs

	return nil
}

func (o contentDigestAlgorithmPreferencesOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

func addParameter(
	parameters *[]parameterOption,
	existing []parameterOption,
	option parameterOption,
	copyBytes bool,
) error {
	switch SignatureParameter(option.name) {
	case Created, Expires, KeyID, Alg, Nonce, Tag:
		return fmt.Errorf("%w: %q is a reserved signature parameter", ErrParameter, option.name)
	}

	value := option.value
	switch v := value.(type) {
	case Token:
		value = httpsfv.Token(v)
	case int:
		value = int64(v)
	case string, bool, int64, float64, []byte, httpsfv.Token:
	default:
		return fmt.Errorf("%w: unsupported value type %T for signature parameter %q", ErrParameter, value, option.name)
	}

	if err := validateParameter(option.name, value); err != nil {
		return err
	}

	for _, param := range existing {
		if param.name == option.name {
			return fmt.Errorf("%w: duplicate signature parameter %q", ErrParameter, option.name)
		}
	}
	for _, param := range *parameters {
		if param.name == option.name {
			return fmt.Errorf("%w: duplicate signature parameter %q", ErrParameter, option.name)
		}
	}

	if copyBytes {
		if v, ok := value.([]byte); ok {
			value = bytes.Clone(v)
		}
	}

	*parameters = append(*parameters, parameterOption{name: option.name, value: value})

	return nil
}

func validateParameter(name string, value any) error {
	validationParams := httpsfv.NewParams()
	validationParams.Add(name, value)

	if _, err := httpsfv.Marshal(httpsfv.Item{Value: true, Params: validationParams}); err != nil {
		return fmt.Errorf("%w: invalid signature parameter %q: %v", ErrParameter, name, err)
	}

	return nil
}
