package httpsig

import (
	"bytes"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/dunglas/httpsfv"
)

type signOptions struct {
	label            string
	nonce            string
	nonceSet         bool
	staticParameters []parameterOption
	parameters       []parameterOption
}

type acceptSignatureBuildOptions struct {
	nonce            string
	nonceSet         bool
	staticParameters []parameterOption
	parameters       []parameterOption
}

type sigNegotiationOptions struct {
	opts []AcceptSignatureOption
}

// SignerOption configures the signing policy of a Signer.
type SignerOption interface {
	applySignerOption(s *signer) error
}

// SignOption configures a single Sign call.
type SignOption interface {
	applySignOption(opts *signOptions) error
}

// SignatureNegotiationOption configures requests additional to the verifier's
// signature requirements.
type SignatureNegotiationOption interface {
	applySignatureNegotiationOption(opts *sigNegotiationOptions)
}

// VerifierOption configures signature selection or verification requirements.
// It can also be used within WithRequiredTag for per-tag requirements.
type VerifierOption interface {
	applyVerifierOption(v *verifier, e *verificationPolicy, inTag bool) error
}

// VerifyOption adds requirements for a single Verify call.
type VerifyOption interface {
	applyVerifyOption(e *verificationPolicy) error
}

// AcceptSignatureOption configures an AcceptSignatureBuilder.
type AcceptSignatureOption interface {
	applyAcceptSignatureOption(builder *AcceptSignatureBuilder) error
}

// AcceptSignatureBuildOption configures a single AcceptSignatureBuilder.Build call.
type AcceptSignatureBuildOption interface {
	applyAcceptSignatureBuildOption(opts *acceptSignatureBuildOptions) error
}

type signerOptionFunc func(*signer) error

func (f signerOptionFunc) applySignerOption(s *signer) error {
	return f(s)
}

type verifierOptionFunc func(*verifier, *verificationPolicy, bool) error

func (f verifierOptionFunc) applyVerifierOption(v *verifier, e *verificationPolicy, inTag bool) error {
	return f(v, e, inTag)
}

// WithLabel specifies the technical label for a signature or an
// Accept-Signature request. An empty label leaves the current label unchanged.
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

// WithTTL specifies the interval between the created and expires signature
// parameters. A non-positive duration omits expires.
func WithTTL(ttl time.Duration) SignerOption {
	return signerOptionFunc(func(s *signer) error {
		s.ttl = ttl

		return nil
	})
}

// WithComponents specifies component identifiers to cover when signing,
// require during verification, or request in Accept-Signature.
// For `@query-param`, the `name` component parameter must contain the
// canonical percent-encoded parameter name. For example, use
// `"@query-param";name="x%2By"` for a query parameter named `x+y`; a literal
// `+` in `name` is rejected.
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

func (o componentsOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	var err error

	policy.identifiers, err = toComponentIdentifiers(o.identifiers)

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

// WithTag specifies an application-defined tag for signing or
// Accept-Signature requests.
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

// WithContentDigestAlgorithm selects the algorithm for generating a covered
// Content-Digest. An unsupported algorithm causes ErrUnsupportedAlgorithm.
func WithContentDigestAlgorithm(alg DigestAlgorithm) SignerOption {
	return signerOptionFunc(func(s *signer) error {
		if _, known := supportedAlgs[alg]; !known {
			return fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
		}

		s.cdAlg = alg

		return nil
	})
}

// WithKeyID specifies the keyid parameter for signing or Accept-Signature.
// An empty value is ignored when signing and omitted from Accept-Signature.
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

// WithAlg includes the selected Key.Algorithm as the alg signature parameter.
// It does not select or change the signing algorithm.
func WithAlg() SignerOption {
	return signerOptionFunc(func(s *signer) error {
		s.includeAlg = true

		return nil
	})
}

// WithParameter specifies an extension parameter for signing, verifying, or
// requesting a signature, either statically or for a single call. It can also
// be used in WithSignatureNegotiation. Extension values may be
// string, Token, DisplayString, time.Time (RFC 9651 Date), bool, int, int64,
// float64, or []byte. DisplayString must contain valid UTF-8, and Date values
// are transmitted with second precision. Standard RFC 9421
// parameter names are reserved, except for a non-empty string nonce on Verify,
// Sign, or AcceptSignatureBuilder.Build. Verification requirements are additive;
// an invocation cannot override static requirements. Duplicate signing or
// builder parameters are rejected.
func WithParameter(name SignatureParameter, value any) parameterOption {
	return parameterOption{name: name, value: value}
}

type parameterOption struct {
	name  SignatureParameter
	value any
}

func (o parameterOption) applySignerOption(s *signer) error {
	return addParameter(&s.parameters, nil, o, true)
}

func (o parameterOption) applySignOption(opts *signOptions) error {
	if o.name == Nonce {
		if opts.nonceSet {
			return fmt.Errorf("%w: duplicate signature parameter %q", ErrParameter, o.name)
		}

		nonce, err := validateNonceOption(o.value)
		if err != nil {
			return err
		}

		opts.nonce = nonce
		opts.nonceSet = true

		return nil
	}

	return addParameter(&opts.parameters, opts.staticParameters, o, false)
}

func (o parameterOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	return addParameter(&asb.parameters, nil, o, true)
}

func (o parameterOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

func (o parameterOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	return o.applyVerifyOption(policy)
}

func (o parameterOption) applyVerifyOption(policy *verificationPolicy) error {
	return policy.addExpectedParameter(o)
}

// WithRequiredParameters requires the named signature parameters to be present.
// It does not check their application-specific semantics.
func WithRequiredParameters(names ...SignatureParameter) requiredParametersOption {
	return names
}

type requiredParametersOption []SignatureParameter

func (o requiredParametersOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	return o.applyVerifyOption(policy)
}

func (o requiredParametersOption) applyVerifyOption(policy *verificationPolicy) error {
	for _, name := range o {
		if err := policy.addRequiredParameter(name); err != nil {
			return err
		}
	}

	return nil
}

// WithForbiddenParameters rejects signatures containing any named parameter.
func WithForbiddenParameters(names ...SignatureParameter) forbiddenParametersOption {
	return names
}

type forbiddenParametersOption []SignatureParameter

func (o forbiddenParametersOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	return o.applyVerifyOption(policy)
}

func (o forbiddenParametersOption) applyVerifyOption(policy *verificationPolicy) error {
	for _, name := range o {
		if err := policy.addForbiddenParameter(name); err != nil {
			return err
		}
	}

	return nil
}

func (o parameterOption) applyAcceptSignatureBuildOption(opts *acceptSignatureBuildOptions) error {
	if o.name == Nonce {
		if opts.nonceSet {
			return fmt.Errorf("%w: duplicate signature parameter %q", ErrParameter, o.name)
		}

		nonce, err := validateNonceOption(o.value)
		if err != nil {
			return err
		}

		opts.nonce = nonce
		opts.nonceSet = true

		return nil
	}

	return addParameter(&opts.parameters, opts.staticParameters, o, false)
}

func validateNonceOption(value any) (string, error) {
	nonce, ok := value.(string)
	if !ok || nonce == "" {
		return "", fmt.Errorf("%w: nonce must be a non-empty string", ErrParameter)
	}

	if err := validateParameter(Nonce, nonce); err != nil {
		return "", err
	}

	return nonce, nil
}

// WithValidityTolerance specifies the allowed clock skew for created and
// expires timestamp checks. The duration must not be negative; zero allows
// no clock skew.
func WithValidityTolerance(tolerance time.Duration) VerifierOption {
	return verifierOptionFunc(func(_ *verifier, e *verificationPolicy, _ bool) error {
		if tolerance < 0 {
			return fmt.Errorf("%w: validity tolerance must not be negative", ErrParameter)
		}

		e.tolerance = &tolerance

		return nil
	})
}

// WithMaxAge specifies the maximum allowed age of a signature with a
// created timestamp. The duration must be positive.
func WithMaxAge(age time.Duration) VerifierOption {
	return verifierOptionFunc(func(_ *verifier, e *verificationPolicy, _ bool) error {
		if age <= 0 {
			return fmt.Errorf("%w: max age must be positive", ErrParameter)
		}

		e.maxAge = &age

		return nil
	})
}

// WithoutMaxAge disables the maximum age check for signatures with a created
// timestamp. Checks for future created timestamps and signature expiration
// remain active.
func WithoutMaxAge() VerifierOption {
	return verifierOptionFunc(func(_ *verifier, e *verificationPolicy, _ bool) error {
		e.maxAge = new(time.Duration)

		return nil
	})
}

// WithRequiredTag specifies a required application-defined tag and its
// per-tag verifier options. Each non-empty tag may be configured only once.
func WithRequiredTag(tag string, opts ...VerifierOption) VerifierOption {
	return verifierOptionFunc(func(ver *verifier, _ *verificationPolicy, f bool) error {
		if f {
			panic("WithRequiredTag cannot be used as option for itself")
		}

		if len(tag) == 0 {
			return fmt.Errorf("%w: required tag must not be empty", ErrParameter)
		}

		if _, configured := ver.tagPolicies[tag]; configured {
			return fmt.Errorf("%w: requirements for tag %s are already configured", ErrParameter, tag)
		}

		policy := &verificationPolicy{}

		for _, opt := range opts {
			if err := opt.applyVerifierOption(ver, policy, true); err != nil {
				return err
			}
		}

		ver.tagPolicies[tag] = policy

		return nil
	})
}

// WithValidateAllSignatures selects all signatures for verification, rather
// than only those with required tags.
func WithValidateAllSignatures() VerifierOption {
	return verifierOptionFunc(func(v *verifier, _ *verificationPolicy, _ bool) error {
		v.validateAllSigs = true

		return nil
	})
}

// WithCreatedTimestamp specifies whether the created parameter is required
// during verification or requested in Accept-Signature. False makes it
// optional during verification and omits it from Accept-Signature.
func WithCreatedTimestamp(flag bool) createdTimestampOption {
	return createdTimestampOption(flag)
}

type createdTimestampOption bool

func (o createdTimestampOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	flag := bool(o)
	policy.reqCreatedTS = &flag

	return nil
}

func (o createdTimestampOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.addCreatedTS = bool(o)

	return nil
}

// WithExpiresTimestamp specifies whether the expires parameter is required
// during verification or requested in Accept-Signature. False makes it
// optional during verification and omits it from Accept-Signature.
func WithExpiresTimestamp(flag bool) expiredTimestampOption {
	return expiredTimestampOption(flag)
}

type expiredTimestampOption bool

func (o expiredTimestampOption) applyVerifierOption(_ *verifier, policy *verificationPolicy, _ bool) error {
	flag := bool(o)
	policy.reqExpiresTS = &flag

	return nil
}

func (o expiredTimestampOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	asb.addExpiresTS = bool(o)

	return nil
}

// WithSignatureNegotiation enables Accept-Signature negotiation based on the
// verifier's requirements. Its options specify additional requests that cannot
// be derived from those requirements.
func WithSignatureNegotiation(opts ...SignatureNegotiationOption) VerifierOption {
	no := &sigNegotiationOptions{opts: make([]AcceptSignatureOption, 0, len(opts))}
	for _, opt := range opts {
		opt.applySignatureNegotiationOption(no)
	}

	return verifierOptionFunc(func(_ *verifier, policy *verificationPolicy, _ bool) error {
		builder, err := NewAcceptSignature(no.opts...)
		if err != nil {
			return err
		}

		policy.asb = builder

		return nil
	})
}

// WithSignatureAlgorithm specifies an alg parameter to request in
// Accept-Signature. It does not select a signing algorithm.
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

// WithNonceGetter configures a nonce source for Accept-Signature, including
// verifier-based negotiation. A nil getter leaves the source unchanged.
func WithNonceGetter(ng NonceGetter) nonceGetterOption {
	return nonceGetterOption{getter: ng}
}

type nonceGetterOption struct {
	getter NonceGetter
}

func (o nonceGetterOption) applyAcceptSignatureOption(asb *AcceptSignatureBuilder) error {
	if o.getter != nil {
		asb.nonceGetter = o.getter
	}

	return nil
}

func (o nonceGetterOption) applySignatureNegotiationOption(opts *sigNegotiationOptions) {
	opts.opts = append(opts.opts, o)
}

// WithContentDigestAlgorithmPreferences specifies the algorithms and
// preferences to request in Want-Content-Digest.
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

//nolint:cyclop
func addParameter(
	parameters *[]parameterOption,
	existing []parameterOption,
	option parameterOption,
	copyBytes bool,
) error {
	var err error

	option, err = normalizeParameter(option)
	if err != nil {
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
		if v, ok := option.value.([]byte); ok {
			option.value = bytes.Clone(v)
		}
	}

	*parameters = append(*parameters, option)

	return nil
}

func normalizeParameter(option parameterOption) (parameterOption, error) {
	switch option.name {
	case Created, Expires, KeyID, Alg, Nonce, Tag:
		return option, fmt.Errorf("%w: %q is a reserved signature parameter", ErrParameter, option.name)
	}

	switch v := option.value.(type) {
	case Token:
		option.value = httpsfv.Token(v)
	case DisplayString:
		if !utf8.ValidString(string(v)) {
			return option, fmt.Errorf("%w: invalid UTF-8 in signature parameter %q", ErrParameter, option.name)
		}

		option.value = httpsfv.DisplayString(v)
	case time.Time:
		// RFC 9651 Date values have Unix-second precision.
		option.value = time.Unix(v.Unix(), 0).UTC()
	case int:
		option.value = int64(v)
	case string, bool, int64, float64, []byte, httpsfv.Token:
	default:
		return option, fmt.Errorf("%w: unsupported value type %T for signature parameter %q",
			ErrParameter, option.value, option.name)
	}

	if err := validateParameter(option.name, option.value); err != nil {
		return option, err
	}

	return option, nil
}

func validateParameter(name SignatureParameter, value any) error {
	validationParams := httpsfv.NewParams()
	validationParams.Add(string(name), value)

	if _, err := httpsfv.Marshal(httpsfv.Item{Value: true, Params: validationParams}); err != nil {
		return fmt.Errorf("%w: invalid signature parameter %q: %w", ErrParameter, name, err)
	}

	return nil
}
