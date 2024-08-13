package httpsig

import (
	"fmt"
	"slices"
	"time"

	"github.com/dunglas/httpsfv"
)

type signatureParameters struct {
	httpsfv.InnerList

	created     time.Time
	expires     time.Time
	nonce       string
	alg         SignatureAlgorithm
	keyID       string
	tag         string
	identifiers []*componentIdentifier
}

func newSignatureParameters(
	created, expires time.Time,
	nonce, keyID, signatureTag string,
	algorithm SignatureAlgorithm,
	identifiers []*componentIdentifier,
) *signatureParameters {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-parameters
	params := httpsfv.NewParams()

	if !created.Equal(time.Time{}) {
		params.Add(string(Created), created.Unix())
	}

	if !expires.Equal(time.Time{}) {
		params.Add(string(Expires), expires.Unix())
	}

	if len(keyID) != 0 {
		params.Add(string(KeyID), keyID)
	}

	if len(algorithm) != 0 {
		params.Add(string(Alg), string(algorithm))
	}

	if len(nonce) != 0 {
		params.Add(string(Nonce), nonce)
	}

	if len(signatureTag) != 0 {
		params.Add(string(Tag), signatureTag)
	}

	items := make([]httpsfv.Item, len(identifiers))
	for i, id := range identifiers {
		items[i] = id.Item
	}

	return &signatureParameters{
		InnerList:   httpsfv.InnerList{Params: params, Items: items},
		created:     created,
		expires:     expires,
		nonce:       nonce,
		alg:         algorithm,
		keyID:       keyID,
		tag:         signatureTag,
		identifiers: identifiers,
	}
}

//nolint:funlen, cyclop
func (p *signatureParameters) fromInnerList(list httpsfv.InnerList) error {
	for _, item := range list.Items {
		ci, err := newComponentIdentifier(item)
		if err != nil {
			return err
		}

		p.identifiers = append(p.identifiers, ci)
	}

	for _, name := range list.Params.Names() {
		param, _ := list.Params.Get(name)

		switch SignatureParameter(name) {
		case Created:
			value, ok := param.(int64)
			if !ok {
				return fmt.Errorf("%w: created", ErrMalformedSignatureParameter)
			}

			p.created = time.Unix(value, 0).UTC()
		case Expires:
			value, ok := param.(int64)
			if !ok {
				return fmt.Errorf("%w: expires", ErrMalformedSignatureParameter)
			}

			p.expires = time.Unix(value, 0).UTC()
		case KeyID:
			value, ok := param.(string)
			if !ok {
				return fmt.Errorf("%w: keyid", ErrMalformedSignatureParameter)
			}

			p.keyID = value
		case Alg:
			value, ok := param.(string)
			if !ok {
				return fmt.Errorf("%w: alg", ErrMalformedSignatureParameter)
			}

			p.alg = SignatureAlgorithm(value)
		case Nonce:
			value, ok := param.(string)
			if !ok {
				return fmt.Errorf("%w: nonce", ErrMalformedSignatureParameter)
			}

			p.nonce = value
		case Tag:
			value, ok := param.(string)
			if !ok {
				return fmt.Errorf("%w: tag", ErrMalformedSignatureParameter)
			}

			p.tag = value
		default:
			return fmt.Errorf("%w: %s is unknown", ErrMalformedSignatureParameter, name)
		}
	}

	p.Params = list.Params
	p.Items = list.Items

	return nil
}

func (p *signatureParameters) toSignatureBase(msg *Message) ([]byte, error) {
	marshalledSigParams, err := httpsfv.Marshal(p.InnerList)
	if err != nil {
		return nil, err
	}

	sigBase := make(componentList, 0, len(p.identifiers))

	for _, ci := range p.identifiers {
		comp, err := ci.createComponent(msg)
		if err != nil {
			return nil, err
		}

		sigBase = append(sigBase, comp)
	}

	sigBase = append(sigBase, component{
		key:   &componentIdentifier{Item: httpsfv.NewItem("@signature-params")},
		value: []string{marshalledSigParams},
	})

	base, err := sigBase.marshal()
	if err != nil {
		return nil, err
	}

	return []byte(base), nil
}

func (p *signatureParameters) hasIdentifier(id *componentIdentifier) bool {
	for _, identifier := range p.identifiers {
		if identifier.Item.Value == id.Item.Value && slices.Equal(identifier.Params.Names(), id.Params.Names()) {
			return true
		}
	}

	return false
}
