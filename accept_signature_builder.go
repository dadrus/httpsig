package httpsig

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

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
		if err := opt.applyAcceptSignatureOption(asb); err != nil {
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
