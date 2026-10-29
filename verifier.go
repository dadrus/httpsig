package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// VerifiedSignature contains the attributes of a successfully verified HTTP
// message signature and the metadata returned by the KeyResolver.
type VerifiedSignature struct {
	// Label is the received signature label. It is not cryptographically
	// protected and must not be used as an identity or authorization claim.
	Label string

	// Components contains the canonicalized values of the covered HTTP
	// message components, without the synthetic @signature-params component.
	Components map[string]string

	// Parameters contains the actual transmitted signature parameters,
	// including extensions, without synthetic defaults.
	Parameters SignatureParameters

	// Metadata is the application-defined metadata provided by the KeyResolver
	// for this signature.
	Metadata any
}

// VerificationResult contains the signatures selected and successfully
// verified during one call to Verifier.Verify.
type VerificationResult []VerifiedSignature

// Verifier verifies HTTP message signatures according to its configured
// requirements. A call succeeds only if all selected signatures pass.
type Verifier interface {
	// Verify returns information about the successfully verified signatures
	// or an error.
	Verify(msg *Message) (VerificationResult, error)
}

// VerifierOption configures which signatures to verify and which generic
// checks to apply. Options can be provided to NewVerifier or used within
// WithRequiredTag for per-tag expectations. Options such as WithNonceChecker
// configure the verifier globally even when supplied within a tag.
type VerifierOption func(v *verifier, e *expectations, f bool) error

// WithRequiredComponents specifies HTTP fields or derived component
// identifiers that must be covered by a signature to which the option applies.
func WithRequiredComponents(identifiers ...string) VerifierOption {
	return func(_ *verifier, exp *expectations, _ bool) error {
		var err error

		exp.identifiers, err = toComponentIdentifiers(identifiers)

		return err
	}
}

// WithValidityTolerance allows a clock skew of d when checking the created
// and expires signature parameters.
func WithValidityTolerance(d time.Duration) VerifierOption {
	return func(_ *verifier, e *expectations, _ bool) error {
		e.tolerance = d

		return nil
	}
}

// WithMaxAge sets the maximum age of signatures with a created timestamp.
// The default for NewVerifier is 30 seconds.
func WithMaxAge(d time.Duration) VerifierOption {
	return func(_ *verifier, e *expectations, _ bool) error {
		e.maxAge = d

		return nil
	}
}

// WithNonceChecker sets the checker for the nonce parameter, including when
// the parameter is absent. If checker is nil, the no-op default remains. CheckNonce
// may be called before cryptographic verification has succeeded; checkers
// with replay state must account for unsuccessful verification attempts.
func WithNonceChecker(checker NonceChecker) VerifierOption {
	// TODO: Maybe we should use checker after cryptographic verification has succeeded
	return func(v *verifier, _ *expectations, _ bool) error {
		if checker != nil {
			v.nonceChecker = checker
		}

		return nil
	}
}

// WithRequiredTag selects signatures with the given application tag and
// applies opts to that signature. Global options in NewVerifier provide
// defaults for unspecified per-tag requirements. Each tag may be configured
// only once.
func WithRequiredTag(tag string, opts ...VerifierOption) VerifierOption {
	return func(ver *verifier, _ *expectations, f bool) error {
		if f {
			panic("WithRequiredTag cannot be used as option for itself")
		}

		// TODO: check if the tag is empty, which is reserved for global expectations. such tag is not allowed

		if _, configured := ver.tagExpectations[tag]; configured {
			return fmt.Errorf("%w: requirements for tag %s are already configured", ErrParameter, tag)
		}

		exp := &expectations{
			tolerance: -1,
			maxAge:    -1,
		}

		for _, opt := range opts {
			if err := opt(ver, exp, true); err != nil {
				return err
			}
		}

		ver.tagExpectations[tag] = exp

		return nil
	}
}

// WithValidateAllSignatures verifies every signature in the message, not just
// those selected with WithRequiredTag. When a signature has a configured tag,
// its per-tag requirements apply; otherwise, global requirements apply.
func WithValidateAllSignatures() VerifierOption {
	return func(v *verifier, _ *expectations, _ bool) error {
		v.validateAllSigs = true

		return nil
	}
}

// WithCreatedTimestampRequired controls whether the created parameter must
// be present. If present, it is still checked even when flag is false.
// NewVerifier requires created by default.
func WithCreatedTimestampRequired(flag bool) VerifierOption {
	// TODO: Same challenge as WithExpiredTimestampRequired
	return func(_ *verifier, exp *expectations, _ bool) error {
		exp.reqCreatedTS = &flag

		return nil
	}
}

// WithExpiredTimestampRequired controls whether the expires parameter must
// be present. If present, it is still checked even when flag is false.
// NewVerifier requires expires by default.
func WithExpiredTimestampRequired(flag bool) VerifierOption {
	// TODO: if the flag is false, then the expires parameter must not be present in the signature. This must be checked.
	// There is a need to think more about the semantics as different rfcs have different requirements on that parameter
	return func(_ *verifier, exp *expectations, _ bool) error {
		exp.reqExpiresTS = &flag

		return nil
	}
}

// WithSignatureNegotiation enables Accept-Signature negotiation when a
// required signature or required component or parameter is missing.
//
// Negotiation reuses the relevant verifier requirements; opts specify only
// additional requests such as a key ID, nonce, algorithm, or label. A caller
// can extract NoApplicableSignatureError from a verification failure and call
// its Negotiate method to populate response headers. Negotiation configured
// globally cannot be combined with WithValidateAllSignatures.
func WithSignatureNegotiation(opts ...SignatureNegotiationOption) VerifierOption {
	no := &sigNegotiationOpts{opts: make([]AcceptSignatureOption, 0, len(opts))}
	for _, opt := range opts {
		opt(no)
	}

	return func(_ *verifier, exp *expectations, _ bool) error {
		builder, err := NewAcceptSignature(no.opts...)
		if err != nil {
			return err
		}

		exp.asb = builder

		return nil
	}
}

type sigNegotiationOpts struct {
	opts []AcceptSignatureOption
}

// SignatureNegotiationOption configures the additional values requested by
// WithSignatureNegotiation beyond the verifier's existing requirements.
type SignatureNegotiationOption func(sno *sigNegotiationOpts)

// WithRequestedSignatureAlgorithm requests alg in the generated
// Accept-Signature header.
func WithRequestedSignatureAlgorithm(alg SignatureAlgorithm) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedSignatureAlgorithm(alg))
	}
}

// WithRequestedNonce supplies the nonce source for Accept-Signature
// negotiation.
func WithRequestedNonce(ng NonceGetter) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedNonce(ng))
	}
}

// WithRequestedContentDigestAlgorithmPreferences sets the Want-Content-Digest
// preferences emitted when negotiation requires a content-digest component.
func WithRequestedContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithContentDigestAlgorithmPreferences(prefs...))
	}
}

// WithRequestedLabel sets the technical label requested in Accept-Signature.
// Signature labels are not authenticated and must not carry identity meaning.
func WithRequestedLabel(label string) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedLabel(label))
	}
}

// WithRequestedKeyID requests keyID as the keyid parameter in the generated
// Accept-Signature header.
func WithRequestedKeyID(keyID string) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedKeyID(keyID))
	}
}

// NewVerifier creates a Verifier instance.
// Without WithValidateAllSignatures, at least one WithRequiredTag is necessary.
// By default, created and expires are required and signatures may be at most
// 30 seconds old. More specific requirements can be set through opts.
//
//nolint:cyclop
func NewVerifier(resolver KeyResolver, opts ...VerifierOption) (Verifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("%w: no key resolver provided", ErrVerifierCreation)
	}

	trueValue := true

	ver := &verifier{
		keyResolver:     resolver,
		tagExpectations: make(map[string]*expectations),
		nonceChecker:    noopNonceChecker{},
	}

	global := &expectations{
		maxAge:       30 * time.Second, //nolint:mnd
		reqExpiresTS: &trueValue,
		reqCreatedTS: &trueValue,
	}

	for _, opt := range opts {
		if err := opt(ver, global, false); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerifierCreation, err)
		}
	}

	if !ver.validateAllSigs && len(ver.tagExpectations) == 0 {
		return nil, fmt.Errorf("%w: validation of all signatures disabled, but no signature tags specified",
			ErrVerifierCreation)
	}

	if global.asb != nil && ver.validateAllSigs {
		return nil, fmt.Errorf("%w: verification and negotiation of all posible signature is not possible",
			ErrVerifierCreation)
	}

	if global.asb != nil {
		global.asb.setIdentifiers(global.identifiers)
	}

	for tag, exp := range ver.tagExpectations {
		if exp.tolerance == -1 {
			exp.tolerance = global.tolerance
		}

		if exp.maxAge == -1 {
			exp.maxAge = global.maxAge
		}

		if len(global.identifiers) != 0 && len(exp.identifiers) == 0 {
			exp.identifiers = global.identifiers
		}

		if exp.reqExpiresTS == nil {
			exp.reqExpiresTS = global.reqExpiresTS
		}

		if exp.reqCreatedTS == nil {
			exp.reqCreatedTS = global.reqCreatedTS
		}

		if global.asb != nil && exp.asb == nil {
			// create a copy
			tmp := *global.asb
			exp.asb = &tmp
		}

		if exp.asb != nil {
			exp.asb.setIdentifiers(exp.identifiers)
			exp.asb.tag = tag
			exp.asb.addCreatedTS = *exp.reqCreatedTS
			exp.asb.addExpiresTS = *exp.reqExpiresTS
		}
	}

	if ver.validateAllSigs {
		ver.tagExpectations[""] = global
	}

	return ver, nil
}

type payloadVerifier interface {
	verifyPayload(data []byte, signature []byte) error
}

func newPayloadVerifier(verificationKey any, alg SignatureAlgorithm) (payloadVerifier, error) {
	switch publicKey := verificationKey.(type) {
	case ed25519.PublicKey:
		return newEd25519Verifier(publicKey, alg)
	case *rsa.PublicKey:
		return newRSAVerifier(publicKey, alg)
	case *ecdsa.PublicKey:
		return newECDSAVerifier(publicKey, alg)
	case []byte:
		return newSymmetricSigner(publicKey, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

type expectations struct {
	tolerance    time.Duration
	maxAge       time.Duration
	identifiers  []*componentIdentifier
	asb          *AcceptSignatureBuilder
	reqCreatedTS *bool
	reqExpiresTS *bool
}

// nolint: funlen, cyclop
func (e *expectations) assert(
	si *signatureInput,
	msg *Message,
	keyAlg SignatureAlgorithm,
	nc NonceChecker,
) error {
	var (
		missingComponents []string
		cmv               compositeMessageVerifier
		mv                messageVerifier
	)

	nonce := NonceValue{}

	nonceValue, noncePresent := si.nonce()
	if noncePresent {
		nonce.Value = nonceValue
		nonce.Present = true
	}

	if err := nc.CheckNonce(msg.Context, nonce); err != nil {
		return fmt.Errorf("%w: nonce validation failed: %w", ErrParameter, err)
	}

	algorithm, algPresent := si.algorithm()
	if algPresent && algorithm != keyAlg {
		return fmt.Errorf("%w: key algorithm %s does not match signature algorithm %s",
			ErrParameter, algorithm, keyAlg)
	}

	now := currentTime().UTC()

	expires, expiresPresent := si.expires()
	if !expiresPresent {
		if *e.reqExpiresTS {
			return fmt.Errorf("%w: expected expires parameter not present", ErrMissingParameter)
		}
	} else if now.After(expires.Add(e.tolerance)) {
		return fmt.Errorf("%w: signature expired", ErrValidity)
	}

	created, createdPresent := si.created()
	if !createdPresent {
		if *e.reqCreatedTS {
			return fmt.Errorf("%w: expected created parameter not present", ErrMissingParameter)
		}
	} else {
		if now.Before(created.Add(-1 * e.tolerance)) {
			return fmt.Errorf("%w: signature not yet valid", ErrValidity)
		}

		if created.Add(e.maxAge).Before(now) {
			return fmt.Errorf("%w: signature too old", ErrValidity)
		}
	}

	for _, expIdentifier := range e.identifiers {
		if !si.hasIdentifier(expIdentifier) {
			res, _ := httpsfv.Marshal(expIdentifier)
			missingComponents = append(missingComponents, res)
		}
	}

	if len(missingComponents) > 0 {
		return fmt.Errorf("%w: missing component identifiers: %s",
			ErrMissingParameter, strings.Join(missingComponents, ", "))
	}

	for _, id := range si.identifiers {
		if id.Value == "content-digest" {
			_, fromReq := id.Params.Get("req")

			cmv = append(cmv, contentDigester{fromRequest: fromReq})
		}
	}

	if len(cmv) == 0 {
		mv = noopMessageVerifier{}
	} else {
		mv = cmv
	}

	return mv.verify(msg)
}

type verifier struct {
	keyResolver     KeyResolver
	tagExpectations map[string]*expectations
	validateAllSigs bool
	nonceChecker    NonceChecker
}

func (v *verifier) Verify(msg *Message) (VerificationResult, error) {
	sigRefs, err := getSignatureReferences(msg.Header.Values(headerSignatureInput))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	signatureDict, err := httpsfv.UnmarshalDictionary(msg.Header.Values(headerSignature))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	// look if we miss any signatures for configured tags
	if v.hasMissingSignatures(sigRefs) {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg))
	}

	// collect those signatures, which we can verify
	applicableSignatures, err := v.applicableSignatures(sigRefs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	// do the actual verification
	results := make([]VerifiedSignature, 0, len(applicableSignatures))
	for name, params := range applicableSignatures {
		tag, _ := params.tag()

		exp, exists := v.tagExpectations[tag]
		if !exists {
			exp = v.tagExpectations[""]
		}

		signature, err := v.extractSignature(signatureDict, name)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}

		result, err := v.verifySignature(msg, name, signature, params, exp)
		if err != nil {
			if errors.Is(err, ErrMissingParameter) {
				return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg))
			}

			return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}

		results = append(results, result)
	}

	return results, nil
}

func (v *verifier) applicableSignatures(refs map[string]*signatureInput) (map[string]*signatureInput, error) {
	if !v.validateAllSigs {
		for name, input := range refs {
			tag, present := input.tag()
			if !present {
				delete(refs, name)

				continue
			}

			if _, required := v.tagExpectations[tag]; !required {
				delete(refs, name)
			}
		}
	}

	if len(refs) == 0 {
		return nil, &NoApplicableSignatureError{}
	}

	return refs, nil
}

func (v *verifier) negotiateSignatureParameters(msg *Message) error {
	hdr := http.Header{}

	for sigTag, exp := range v.tagExpectations {
		if exp.asb == nil || len(sigTag) == 0 {
			continue
		}

		err := exp.asb.Build(msg.Context, hdr)
		if err != nil {
			return fmt.Errorf("%w: failed to negotiate signature for tag %s: %w", ErrSignatureNegotiationError, sigTag, err)
		}
	}

	return &NoApplicableSignatureError{headerToAdd: hdr}
}

func (v *verifier) hasMissingSignatures(sigRefs map[string]*signatureInput) bool {
	for sigTag := range v.tagExpectations {
		if len(sigTag) == 0 {
			// empty tag is used for expectations for all signatures
			// ignoring it
			continue
		}

		var present bool

		for _, sigRef := range sigRefs {
			tag, tagPresent := sigRef.tag()
			if tagPresent && tag == sigTag {
				present = true

				break
			}
		}

		if !present {
			return true
		}
	}

	return false
}

func (v *verifier) verifySignature(
	msg *Message,
	label string,
	signature []byte,
	si *signatureInput,
	exp *expectations,
) (VerifiedSignature, error) {
	base, err := newSignatureBase(si, msg)
	if err != nil {
		return VerifiedSignature{}, err
	}

	components, err := base.components()
	if err != nil {
		return VerifiedSignature{}, err
	}

	params := si.parameters()

	keyInfo, err := v.keyResolver.ResolveKey(msg.Context, SignatureInfo{
		Label:      label,
		Message:    msg,
		Components: components,
		Parameters: params,
	})
	if err != nil {
		return VerifiedSignature{}, err
	}

	if err = exp.assert(si, msg, keyInfo.Key.Algorithm, v.nonceChecker); err != nil {
		return VerifiedSignature{}, err
	}

	verifier, err := newPayloadVerifier(keyInfo.Key.Material, keyInfo.Key.Algorithm)
	if err != nil {
		return VerifiedSignature{}, err
	}

	sb, err := base.marshal()
	if err != nil {
		return VerifiedSignature{}, err
	}

	err = verifier.verifyPayload(sb, signature)
	if err != nil {
		return VerifiedSignature{}, err
	}

	return VerifiedSignature{
		Label:      label,
		Components: components,
		Parameters: params,
		Metadata:   keyInfo.Metadata,
	}, nil
}

func getSignatureReferences(values []string) (map[string]*signatureInput, error) {
	inputDict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
	}

	sigRefs := make(map[string]*signatureInput, len(inputDict.Names()))

	for _, label := range inputDict.Names() {
		m, _ := inputDict.Get(label)

		sigParams, ok := m.(httpsfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected signature parameters format", ErrMalformedData)
		}

		si, err := parseSignatureInput(sigParams)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
		}

		sigRefs[label] = si
	}

	return sigRefs, nil
}

func (v *verifier) extractSignature(dict *httpsfv.Dictionary, name string) ([]byte, error) {
	sigItem, ok := dict.Get(name)
	if !ok {
		return nil, fmt.Errorf("%w: no signature present for label %s", ErrMalformedData, name)
	}

	signature, ok := sigItem.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected content type for label %s", ErrMalformedData, name)
	}

	signatureBytes, ok := signature.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected value for label %s", ErrMalformedData, name)
	}

	return signatureBytes, nil
}
