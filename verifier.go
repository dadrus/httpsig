package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
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
// The order of the signatures is not guaranteed.
type VerificationResult []VerifiedSignature

// Verifier verifies HTTP message signatures according to its configured
// requirements. A call succeeds only if all selected signatures pass.
type Verifier interface {
	// Verify returns information about the successfully verified signatures
	// or an error. Per-call requirements do not change the Verifier.
	Verify(msg *Message, opts ...VerifyOption) (VerificationResult, error)
}

// NewVerifier creates a Verifier instance.
// Without WithValidateAllSignatures, at least one WithRequiredTag is necessary.
// By default, created and expires are required and signatures may be at most
// 30 seconds old. Optional created or expires parameters are still checked
// when present. Global WithSignatureNegotiation cannot be combined with
// WithValidateAllSignatures. More specific requirements can be set through opts.
//
//nolint:cyclop
func NewVerifier(resolver KeyResolver, opts ...VerifierOption) (Verifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("%w: no key resolver provided", ErrVerifierCreation)
	}

	ver := &verifier{
		keyResolver: resolver,
		tagPolicies: make(map[string]*verificationPolicy),
	}

	globalPolicy := &verificationPolicy{
		maxAge:       new(30 * time.Second), //nolint:mnd
		reqExpiresTS: new(true),
		reqCreatedTS: new(true),
	}

	for _, opt := range opts {
		if err := opt.applyVerifierOption(ver, globalPolicy, false); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerifierCreation, err)
		}
	}

	if !ver.validateAllSigs && len(ver.tagPolicies) == 0 {
		return nil, fmt.Errorf("%w: validation of all signatures disabled, but no signature tags specified",
			ErrVerifierCreation)
	}

	if globalPolicy.asb != nil && ver.validateAllSigs {
		return nil, fmt.Errorf("%w: verification and negotiation of all posible signature is not possible",
			ErrVerifierCreation)
	}

	for tag, policy := range ver.tagPolicies {
		if err := policy.inherit(globalPolicy, tag); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerifierCreation, err)
		}
	}

	if ver.validateAllSigs {
		if err := globalPolicy.prepare(""); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerifierCreation, err)
		}

		ver.tagPolicies[""] = globalPolicy
	}

	return ver, nil
}

type payloadVerifier interface {
	verify(ctx context.Context, data []byte, signature []byte) error
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

type verifier struct {
	keyResolver     KeyResolver
	tagPolicies     map[string]*verificationPolicy
	validateAllSigs bool
}

func (v *verifier) Verify(msg *Message, opts ...VerifyOption) (VerificationResult, error) {
	policiesByTag, err := v.policiesForCall(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}

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
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg, policiesByTag))
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

		policy, exists := policiesByTag[tag]
		if !exists {
			policy = policiesByTag[""]
		}

		signature, err := v.extractSignature(signatureDict, name)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}

		result, err := v.verifySignature(msg, name, signature, params, policy)
		if err != nil {
			if errors.Is(err, ErrMissingParameter) {
				return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, v.negotiateSignatureParameters(msg, policiesByTag))
			}

			return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
		}

		results = append(results, result)
	}

	return results, nil
}

func (v *verifier) policiesForCall(opts []VerifyOption) (map[string]*verificationPolicy, error) {
	if len(opts) == 0 {
		return v.tagPolicies, nil
	}

	result := make(map[string]*verificationPolicy, len(v.tagPolicies))
	for tag, original := range v.tagPolicies {
		effective, err := original.withOptions(tag, opts)
		if err != nil {
			return nil, err
		}

		result[tag] = effective
	}

	return result, nil
}

func (v *verifier) applicableSignatures(refs map[string]*signatureInput) (map[string]*signatureInput, error) {
	if !v.validateAllSigs {
		for name, input := range refs {
			tag, present := input.tag()
			if !present {
				delete(refs, name)

				continue
			}

			if _, required := v.tagPolicies[tag]; !required {
				delete(refs, name)
			}
		}
	}

	if len(refs) == 0 {
		return nil, &NoApplicableSignatureError{}
	}

	return refs, nil
}

func (v *verifier) negotiateSignatureParameters(msg *Message, policiesByTag map[string]*verificationPolicy) error {
	hdr := http.Header{}

	for sigTag, policy := range policiesByTag {
		if policy.asb == nil || len(sigTag) == 0 {
			continue
		}

		buildOpts := make([]AcceptSignatureBuildOption, len(policy.expectedParameters))
		for i, param := range policy.expectedParameters {
			buildOpts[i] = param
		}

		err := policy.asb.Build(msg.Context, hdr, buildOpts...)
		if err != nil {
			return fmt.Errorf("%w: failed to negotiate signature for tag %s: %w", ErrSignatureNegotiationError, sigTag, err)
		}
	}

	return &NoApplicableSignatureError{headerToAdd: hdr}
}

func (v *verifier) hasMissingSignatures(sigRefs map[string]*signatureInput) bool {
	for sigTag := range v.tagPolicies {
		if len(sigTag) == 0 {
			// empty tag is used for a policy applying to all signatures
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
	policy *verificationPolicy,
) (VerifiedSignature, error) {
	if err := policy.assertMetadata(si, msg); err != nil {
		return VerifiedSignature{}, err
	}

	base, err := newSignatureBase(msg, si, nil)
	if err != nil {
		return VerifiedSignature{}, err
	}

	components := base.components()
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

	if err = policy.assertKeyAlgorithm(si, keyInfo.Key.Algorithm); err != nil {
		return VerifiedSignature{}, err
	}

	verifier, err := newPayloadVerifier(keyInfo.Key.Material, keyInfo.Key.Algorithm)
	if err != nil {
		return VerifiedSignature{}, err
	}

	err = verifier.verify(msg.Context, base.marshal(), signature)
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
