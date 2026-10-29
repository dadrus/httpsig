package httpsig

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// AcceptSignatureOption configures the Accept-Signature request produced by
// NewAcceptSignature and AcceptSignatureBuilder.Build.
type AcceptSignatureOption func(*AcceptSignatureBuilder) error

// WithExpectedSignatureAlgorithm requests that the peer use alg when signing.
// It adds the alg parameter to Accept-Signature.
func WithExpectedSignatureAlgorithm(alg SignatureAlgorithm) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.signatureAlgorithm = alg

		return nil
	}
}

// WithExpectedKeyID requests keyID as the keyid signature parameter in the
// peer's response. An empty ID is omitted by the generated header.
func WithExpectedKeyID(keyID string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.keyID = keyID

		return nil
	}
}

// WithExpectedNonce supplies the nonce source for Accept-Signature.
// If ng is nil, the default random nonce source remains in use.
func WithExpectedNonce(ng NonceGetter) AcceptSignatureOption {
	// TODO: What can we do for profiles which make use of nonces but in a different parameter
	return func(asb *AcceptSignatureBuilder) error {
		if ng != nil {
			asb.nonceGetter = ng
		}

		return nil
	}
}

// WithExpectedLabel sets the dictionary label for Accept-Signature.
// An empty label is ignored. The label is a technical reference, not an
// authenticated identifier, and may be changed by intermediaries.
func WithExpectedLabel(label string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		if len(label) != 0 {
			asb.label = label
		}

		return nil
	}
}

// WithExpectedComponents requests a signature covering the listed HTTP
// fields and derived components. If content-digest is among them, Build also
// adds Want-Content-Digest according to the configured preferences.
func WithExpectedComponents(identifiers ...string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		identifiers, err := toComponentIdentifiers(identifiers)
		if err != nil {
			return err
		}

		asb.setIdentifiers(identifiers)

		return nil
	}
}

// WithContentDigestAlgorithmPreferences sets the preferred digest algorithms
// for Want-Content-Digest when a covered content-digest component is requested.
// Supplying no preferences leaves the defaults unchanged.
func WithContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		if len(prefs) == 0 {
			return nil
		}

		algPrefs := make([]string, len(prefs))

		for i, pref := range prefs {
			if pref.Algorithm == "" {
				return fmt.Errorf("%w: digest algorithm preference requires a non-empty algorithm", ErrParameter)
			}

			algPrefs[i] = pref.String()
		}

		asb.cdAlgPrefs = algPrefs

		return nil
	}
}

// WithExpectedTag requests an application-defined tag on the signature.
// An empty tag is omitted from the generated Accept-Signature field.
func WithExpectedTag(tag string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.tag = tag

		return nil
	}
}

// WithExpectedCreatedTimestamp requests that a signature contain created.
// The request is enabled by default; false removes the requirement.
func WithExpectedCreatedTimestamp(flag bool) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.addCreatedTS = flag

		return nil
	}
}

// WithExpectedExpiresTimestamp requests that a signature contain expires.
// The request is enabled by default; false removes the requirement.
func WithExpectedExpiresTimestamp(flag bool) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.addExpiresTS = flag

		return nil
	}
}

// AlgorithmPreference associates a Content-Digest algorithm with a numeric
// preference value for the Want-Content-Digest header.
type AlgorithmPreference struct {
	// Algorithm is the desired digest algorithm.
	Algorithm DigestAlgorithm
	// Preference is the preference value serialized alongside the algorithm.
	Preference int
}

// String formats the preference as "algorithm=preference".
func (p AlgorithmPreference) String() string {
	return fmt.Sprintf("%s=%d", p.Algorithm, p.Preference)
}

// AcceptSignatureBuilder constructs an Accept-Signature request from the
// configured parameters and component requirements. Use NewAcceptSignature
// to create a builder with defaults, then call Build to add headers.
type AcceptSignatureBuilder struct {
	signatureAlgorithm SignatureAlgorithm
	keyID              string
	nonceGetter        NonceGetter
	label              string
	identifiers        []*componentIdentifier
	cdAlgPrefs         []string
	tag                string
	addCreatedTS       bool
	addExpiresTS       bool
	wantContentDigest  bool
}

// NewAcceptSignature creates an AcceptSignatureBuilder for requesting a
// signature from a peer. By default, it uses label "sig", requests created and
// expires parameters, and generates a random nonce. If Content-Digest is requested,
// the default digest preferences are SHA-256 and SHA-512.
func NewAcceptSignature(opts ...AcceptSignatureOption) (*AcceptSignatureBuilder, error) {
	asb := &AcceptSignatureBuilder{
		addCreatedTS: true,
		addExpiresTS: true,
		nonceGetter:  nonceGetter{},
		label:        "sig",
		cdAlgPrefs: []string{
			AlgorithmPreference{Algorithm: Sha256, Preference: 5}.String(),  //nolint: mnd
			AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(), //nolint: mnd
		},
	}

	for _, opt := range opts {
		if err := opt(asb); err != nil {
			return nil, err
		}
	}

	return asb, nil
}

// Build appends an Accept-Signature header to header using the configured
// signature requirements. If Content-Digest is requested, it also appends
// Want-Content-Digest preferences. The caller must provide a writable, non-nil
// http.Header.
func (asb *AcceptSignatureBuilder) Build(ctx context.Context, header http.Header) error {
	nonce, err := asb.nonceGetter.GetNonce(ctx)
	if err != nil {
		return err
	}

	sigReqs := newSignatureRequirements(
		asb.addCreatedTS,
		asb.addExpiresTS,
		asb.tag,
		nonce,
		asb.keyID,
		asb.signatureAlgorithm,
		asb.identifiers)

	dict := httpsfv.NewDictionary()
	dict.Add(asb.label, sigReqs.InnerList)

	result, err := httpsfv.Marshal(dict)
	if err != nil {
		return err
	}

	header.Add(headerAcceptSignature, result)

	if asb.wantContentDigest {
		for _, pref := range asb.cdAlgPrefs {
			header.Add(headerWantContentDigest, pref)
		}
	}

	return nil
}

func (asb *AcceptSignatureBuilder) setIdentifiers(identifiers []*componentIdentifier) {
	asb.identifiers = identifiers

	for _, identifier := range asb.identifiers {
		if identifier.Value == componentIdentifierContentDigest {
			asb.wantContentDigest = true

			break
		}
	}
}
