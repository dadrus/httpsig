package httpsig

import (
	"context"
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

type Verifier interface {
	Verify(msg *Message) error
}

//go:generate mockery --name KeyResolver --structname KeyResolverMock --inpackage --testonly

// KeyResolver is used to resolve a key id to a verifying key.
type KeyResolver interface {
	ResolveKey(ctx context.Context, keyID string) (Key, error)
}

type payloadVerifier interface {
	verifyPayload(data []byte, signature []byte) error
	algorithm() SignatureAlgorithm
	keyID() string
}

func newPayloadVerifier(verificationKey any, keyID string, alg SignatureAlgorithm) (payloadVerifier, error) {
	switch publicKey := verificationKey.(type) {
	case ed25519.PublicKey:
		return newEd25519Verifier(publicKey, keyID, alg)
	case *rsa.PublicKey:
		return newRSAVerifier(publicKey, keyID, alg)
	case *ecdsa.PublicKey:
		return newECDSAVerifier(publicKey, keyID, alg)
	case []byte:
		return newSymmetricSigner(publicKey, keyID, alg)
	default:
		return nil, ErrUnsupportedKeyType
	}
}

type VerifierOption func(v *verifier, e *expectations, f bool) error

// WithRequiredComponents sets the HTTP fields / derived component names to be included in signing.
func WithRequiredComponents(identifiers ...string) VerifierOption {
	return func(_ *verifier, exp *expectations, _ bool) error {
		var err error

		exp.identifiers, err = toComponentIdentifiers(identifiers)

		return err
	}
}

// WithValidityTolerance sets the clock tolerance for verifying created and expires times.
func WithValidityTolerance(d time.Duration) VerifierOption {
	return func(_ *verifier, e *expectations, _ bool) error {
		e.tolerance = d

		return nil
	}
}

func WithMaxAge(d time.Duration) VerifierOption {
	return func(_ *verifier, e *expectations, _ bool) error {
		e.maxAge = d

		return nil
	}
}

func WithNonceChecker(checker NonceChecker) VerifierOption {
	return func(v *verifier, _ *expectations, _ bool) error {
		if checker != nil {
			v.nonceChecker = checker
		}

		return nil
	}
}

func WithRequiredTag(tag string, opts ...VerifierOption) VerifierOption {
	return func(ver *verifier, _ *expectations, f bool) error {
		if f {
			panic("WithRequiredTag cannot be used as option for itself")
		}

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

func WithValidateAllSignatures() VerifierOption {
	return func(v *verifier, _ *expectations, _ bool) error {
		v.validateAllSigs = true

		return nil
	}
}

func WithCreatedTimestampRequired(flag bool) VerifierOption {
	return func(_ *verifier, exp *expectations, _ bool) error {
		exp.reqCreatedTS = &flag

		return nil
	}
}

func WithExpiredTimestampRequired(flag bool) VerifierOption {
	return func(_ *verifier, exp *expectations, _ bool) error {
		exp.reqExpiresTS = &flag

		return nil
	}
}

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

type SignatureNegotiationOption func(sno *sigNegotiationOpts)

func WithRequestedKey(key Key) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedKey(key))
	}
}

func WithRequestedNonce(ng NonceGetter) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedNonce(ng))
	}
}

func WithRequestedContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithContentDigestAlgorithmPreferences(prefs...))
	}
}

func WithRequestedLabel(label string) SignatureNegotiationOption {
	return func(sno *sigNegotiationOpts) {
		sno.opts = append(sno.opts, WithExpectedLabel(label))
	}
}

// NewVerifier creates a new verifier with the given options.
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

type expectations struct {
	tolerance    time.Duration
	maxAge       time.Duration
	identifiers  []*componentIdentifier
	asb          *AcceptSignatureBuilder
	reqCreatedTS *bool
	reqExpiresTS *bool
}

//nolint:cyclop
func (e *expectations) assert(
	params *signatureParameters,
	msg *Message,
	keyAlg SignatureAlgorithm,
	nc NonceChecker,
) error {
	var (
		nonce             string
		missingComponents []string
		cmv               compositeMessageVerifier
		mv                messageVerifier
	)

	nonceValue, noncePresent := params.Params.Get(string(Nonce))
	if noncePresent {
		nonce = nonceValue.(string) //nolint: forcetypeassert
	}

	if err := nc.CheckNonce(msg.Context, nonce); err != nil {
		return fmt.Errorf("%w: nonce validation failed: %w", ErrParameter, err)
	}

	if len(params.alg) != 0 && params.alg != keyAlg {
		return fmt.Errorf("%w: key algorithm %s does not match signature algorithm %s",
			ErrParameter, params.alg, keyAlg)
	}

	now := currentTime().UTC()

	if params.expires.Equal(time.Time{}) {
		if *e.reqExpiresTS {
			return fmt.Errorf("%w: expected expires parameter not preset", ErrMissingParameter)
		}
	} else if now.After(params.expires.Add(e.tolerance)) {
		return fmt.Errorf("%w: signature expired", ErrValidity)
	}

	if params.created.Equal(time.Time{}) {
		if *e.reqCreatedTS {
			return fmt.Errorf("%w: expected created parameter not preset", ErrMissingParameter)
		}
	} else {
		if now.Before(params.created.Add(-1 * e.tolerance)) {
			return fmt.Errorf("%w: signature not yet valid", ErrValidity)
		}

		if params.created.Add(e.maxAge).Before(now) {
			return fmt.Errorf("%w: signature too old", ErrValidity)
		}
	}

	for _, expIdentifier := range e.identifiers {
		if !params.hasIdentifier(expIdentifier) {
			res, _ := httpsfv.Marshal(expIdentifier)
			missingComponents = append(missingComponents, res)
		}
	}

	if len(missingComponents) > 0 {
		return fmt.Errorf("%w: missing component identifiers: %s",
			ErrMissingParameter, strings.Join(missingComponents, ", "))
	}

	for _, id := range params.identifiers {
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

func (v *verifier) Verify(msg *Message) error {
	sigRefs, err := getSignatureReferences(msg.Header.Values(headerSignatureInput))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	signatureDict, err := httpsfv.UnmarshalDictionary(msg.Header.Values(headerSignature))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	// look if we miss any signatures for configured tags
	if v.hasMissingSignatures(sigRefs) {
		return fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg))
	}

	// collect those signatures, which we can verify
	applicableSignatures, err := v.applicableSignatures(sigRefs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

	// do the actual verification
	for name, params := range applicableSignatures {
		exp, exists := v.tagExpectations[params.tag]
		if !exists {
			exp = v.tagExpectations[""]
		}

		signature, err := v.extractSignature(signatureDict, name)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}

		err = v.verifySignature(msg, signature, params, exp)
		if err != nil {
			if errors.Is(err, ErrMissingParameter) {
				return fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg))
			}

			return fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}
	}

	return nil
}

func (v *verifier) applicableSignatures(refs map[string]*signatureParameters) (map[string]*signatureParameters, error) {
	for name, params := range refs {
		if !v.isApplicable(params.tag) {
			delete(refs, name)
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

func (v *verifier) hasMissingSignatures(sigRefs map[string]*signatureParameters) bool {
	for sigTag := range v.tagExpectations {
		if len(sigTag) == 0 {
			// empty tag is used for expectations for all signatures
			// ignoring it
			continue
		}

		var present bool

		for _, sigRef := range sigRefs {
			if sigRef.tag == sigTag {
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
	signature []byte,
	params *signatureParameters,
	exp *expectations,
) error {
	base, err := params.toSignatureBase(msg)
	if err != nil {
		return err
	}

	key, err := v.keyResolver.ResolveKey(msg.Context, params.keyID)
	if err != nil {
		return err
	}

	if err = exp.assert(params, msg, key.Algorithm, v.nonceChecker); err != nil {
		return err
	}

	verifier, err := newPayloadVerifier(key.Key, key.KeyID, key.Algorithm)
	if err != nil {
		return err
	}

	return verifier.verifyPayload(base, signature)
}

func getSignatureReferences(values []string) (map[string]*signatureParameters, error) {
	inputDict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
	}

	sigRefs := make(map[string]*signatureParameters, len(inputDict.Names()))

	for _, label := range inputDict.Names() {
		var sp signatureParameters

		m, _ := inputDict.Get(label)

		sigParams, ok := m.(httpsfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected signature parameters format", ErrMalformedData)
		}

		if err := sp.fromInnerList(sigParams); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
		}

		sigRefs[label] = &sp
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

func (v *verifier) isApplicable(tag string) bool {
	_, hasKey := v.tagExpectations[tag]

	return v.validateAllSigs || hasKey
}
