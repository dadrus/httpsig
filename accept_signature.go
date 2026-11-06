package httpsig

import (
	"context"
	"errors"
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
	parameters         []parameterOption
	cdAlgPrefs         []string
	tag                string
	addCreatedTS       bool
	addExpiresTS       bool
	wantContentDigest  bool
}

// NewAcceptSignature creates an AcceptSignatureBuilder for requesting a
// signature from a peer. By default, it uses label "sig", requests created
// and expires parameters, and does not request a nonce. If Content-Digest
// is requested, the default digest preferences are SHA-256 and SHA-512.
func NewAcceptSignature(opts ...AcceptSignatureOption) (*AcceptSignatureBuilder, error) {
	asb := &AcceptSignatureBuilder{
		addCreatedTS: true,
		addExpiresTS: true,
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
// Want-Content-Digest preferences. Additional extension parameters can be
// supplied with WithParameter. A non-empty nonce may be provided for this
// call with WithParameter("nonce", value), overriding a configured
// WithNonceGetter without invoking it. Otherwise, the configured getter is
// used if present; if neither is provided, no nonce is requested. Options
// do not modify the builder. The caller must provide a writable, non-nil
// http.Header.
func (asb *AcceptSignatureBuilder) Build(
	ctx context.Context,
	header http.Header,
	opts ...AcceptSignatureBuildOption,
) error {
	callOptions := acceptSignatureBuildOptions{staticParameters: asb.parameters}
	for _, opt := range opts {
		if err := opt.applyAcceptSignatureBuildOption(&callOptions); err != nil {
			return err
		}
	}

	nonce := callOptions.nonce
	if !callOptions.nonceSet && asb.nonceGetter != nil {
		var err error

		nonce, err = asb.nonceGetter.GetNonce(ctx)
		if err != nil {
			return err
		}
	}

	sigReqs := newSignatureRequirements(
		asb.addCreatedTS,
		asb.addExpiresTS,
		asb.tag,
		nonce,
		asb.keyID,
		asb.signatureAlgorithm,
		asb.identifiers)

	for _, param := range asb.parameters {
		sigReqs.Params.Add(string(param.name), param.value)
	}

	for _, param := range callOptions.parameters {
		sigReqs.Params.Add(string(param.name), param.value)
	}

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
	asb.wantContentDigest = false

	for _, identifier := range asb.identifiers {
		if identifier.Value == componentIdentifierContentDigest {
			asb.wantContentDigest = true

			break
		}
	}
}

// SignatureRequest describes a single signature requested by a member of an
// Accept-Signature field. All its values are controlled by the peer. The
// application must decide whether a request is acceptable before signing.
type SignatureRequest struct {
	// Label is the label of the requested signature.
	Label string

	// Components lists the requested component identifiers in their requested
	// order, serialized as Structured Fields Items. Each identifier can be
	// passed to WithComponents.
	Components []string

	// KeyID is the requested keyid parameter. It is empty if not requested.
	KeyID string

	// Algorithm is the requested alg parameter. It is empty if not requested.
	// It is not checked against the supported signature algorithms.
	Algorithm SignatureAlgorithm

	// Tag is the requested tag parameter. It is empty if not requested.
	Tag string

	// Nonce is the requested nonce parameter. It is empty if not requested.
	Nonce string

	// Created reports whether a created timestamp is requested.
	Created bool

	// Expires reports whether an expires timestamp is requested.
	Expires bool

	// Extensions contains the requested parameters not defined by RFC 9421.
	// It is nil if there are none. Its values are decoded as described for
	// SignatureParameters.
	Extensions SignatureParameters
}

// ParseAcceptSignature parses the Accept-Signature fields in header and returns
// the signature requests in the order they appear. It returns an empty result
// if header contains no Accept-Signature field.
//
// If the fields as a whole are not a valid Structured Fields Dictionary, it
// returns no requests and an error wrapping ErrMalformedData. A member that
// cannot be used, for example because it is malformed or names an unsupported
// component, does not affect the other members: the requests of the usable
// members are returned together with a joined error that has an entry wrapping
// ErrMalformedData for each unusable member. RFC 9421 permits ignoring requests
// that cannot be fulfilled, so a non-nil error does not invalidate the returned
// requests. Applications requiring all requests to be usable must check it.
func ParseAcceptSignature(header http.Header) ([]SignatureRequest, error) {
	dict, err := httpsfv.UnmarshalDictionary(header.Values(headerAcceptSignature))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
	}

	labels := dict.Names()
	requests := make([]SignatureRequest, 0, len(labels))

	var errs []error

	for _, label := range labels {
		member, _ := dict.Get(label)

		list, ok := member.(httpsfv.InnerList)
		if !ok {
			errs = append(errs,
				fmt.Errorf("%w: unexpected signature request format for label %q", ErrMalformedData, label))

			continue
		}

		request, err := newSignatureRequest(label, list)
		if err != nil {
			errs = append(errs, fmt.Errorf("%w: label %q: %w", ErrMalformedData, label, err))

			continue
		}

		requests = append(requests, request)
	}

	return requests, errors.Join(errs...)
}

func newSignatureRequest(label string, list httpsfv.InnerList) (SignatureRequest, error) {
	var requirements signatureRequirements

	if err := requirements.fromInnerList(list); err != nil {
		return SignatureRequest{}, err
	}

	components := make([]string, len(requirements.identifiers))

	for i, identifier := range requirements.identifiers {
		component, err := httpsfv.Marshal(identifier.Item)
		if err != nil {
			return SignatureRequest{}, fmt.Errorf("%w: %w", ErrInvalidComponentIdentifier, err)
		}

		components[i] = component
	}

	return SignatureRequest{
		Label:      label,
		Components: components,
		KeyID:      requirements.keyID,
		Algorithm:  requirements.alg,
		Tag:        requirements.tag,
		Nonce:      requirements.nonce,
		Created:    requirements.created,
		Expires:    requirements.expires,
		Extensions: requirements.extensions,
	}, nil
}
