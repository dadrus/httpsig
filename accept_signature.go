package httpsig

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// SignatureRequest describes a single signature requested by a member of an
// Accept-Signature field. All its values are controlled by the peer. The
// application must decide whether a request is acceptable before signing.
type SignatureRequest struct {
	// Label is the label of the requested signature.
	Label string

	// Components lists the requested component identifiers in their requested
	// order, in the form accepted by WithComponents.
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
		component, err := identifier.optionValue()
		if err != nil {
			return SignatureRequest{}, err
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
