package httpsig

import (
	"fmt"
	"slices"
	"time"

	"github.com/dunglas/httpsfv"
)

type signatureInput struct {
	value       httpsfv.InnerList
	identifiers []*componentIdentifier
}

func newSignatureInput(
	identifiers []*componentIdentifier,
	params *httpsfv.Params,
) *signatureInput {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-parameters
	if params == nil {
		params = httpsfv.NewParams()
	}

	items := make([]httpsfv.Item, len(identifiers))
	for i, id := range identifiers {
		items[i] = id.Item
	}

	return &signatureInput{
		value: httpsfv.InnerList{
			Items:  items,
			Params: params,
		},
		identifiers: identifiers,
	}
}

func parseSignatureInput(list httpsfv.InnerList) (*signatureInput, error) {
	identifiers := make([]*componentIdentifier, 0, len(list.Items))

	for _, item := range list.Items {
		identifier, err := newComponentIdentifier(item)
		if err != nil {
			return nil, err
		}

		identifiers = append(identifiers, identifier)
	}

	if err := validateSignatureInputParameters(list.Params); err != nil {
		return nil, err
	}

	return &signatureInput{
		value:       list,
		identifiers: identifiers,
	}, nil
}

func validateSignatureInputParameters(params *httpsfv.Params) error {
	if params == nil {
		return nil
	}

	for _, name := range params.Names() {
		value, _ := params.Get(name)

		switch SignatureParameter(name) {
		case Created, Expires:
			if _, ok := value.(int64); !ok {
				return fmt.Errorf("%w: %s", ErrMalformedSignatureParameter, name)
			}
		case KeyID, Alg, Nonce, Tag:
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%w: %s", ErrMalformedSignatureParameter, name)
			}
		}
	}

	return nil
}

func (si *signatureInput) hasIdentifier(id *componentIdentifier) bool {
	for _, identifier := range si.identifiers {
		if identifier.Value == id.Value && slices.Equal(identifier.Params.Names(), id.Params.Names()) {
			return true
		}
	}

	return false
}

func (si *signatureInput) parameter(name SignatureParameter) (any, bool) {
	if si.value.Params == nil {
		return nil, false
	}

	return si.value.Params.Get(string(name))
}

func (si *signatureInput) stringParameter(name SignatureParameter) (string, bool) {
	value, present := si.parameter(name)
	if !present {
		return "", false
	}

	return value.(string), true
}

func (si *signatureInput) timestamp(name SignatureParameter) (time.Time, bool) {
	value, present := si.parameter(name)
	if !present {
		return time.Time{}, false
	}

	return time.Unix(value.(int64), 0).UTC(), true
}

func (si *signatureInput) algorithm() (SignatureAlgorithm, bool) {
	value, present := si.stringParameter(Alg)

	return SignatureAlgorithm(value), present
}

func (si *signatureInput) created() (time.Time, bool) { return si.timestamp(Created) }
func (si *signatureInput) expires() (time.Time, bool) { return si.timestamp(Expires) }
func (si *signatureInput) nonce() (string, bool)      { return si.stringParameter(Nonce) }
func (si *signatureInput) keyID() (string, bool)      { return si.stringParameter(KeyID) }
func (si *signatureInput) tag() (string, bool)        { return si.stringParameter(Tag) }
