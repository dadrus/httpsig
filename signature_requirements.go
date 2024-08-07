package httpsig

import (
	"fmt"

	"github.com/dunglas/httpsfv"
)

type signatureRequirements struct {
	httpsfv.InnerList

	created     bool
	expires     bool
	nonce       string
	alg         SignatureAlgorithm
	keyID       string
	tag         string
	identifiers []*componentIdentifier
}

func newSignatureRequirements(
	created, expires bool,
	signatureTag, nonce string,
	keyID string,
	algorithm SignatureAlgorithm,
	identifiers []*componentIdentifier,
) *signatureRequirements {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-signature-parameters
	params := httpsfv.NewParams()

	if created {
		params.Add(string(Created), true)
	}

	if expires {
		params.Add(string(Expires), true)
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

	return &signatureRequirements{
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
func (p *signatureRequirements) fromInnerList(list httpsfv.InnerList) error {
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
			value, ok := param.(bool)
			if !ok {
				return fmt.Errorf("%w: created", ErrMalformedSignatureParameter)
			}

			p.created = value
		case Expires:
			value, ok := param.(bool)
			if !ok {
				return fmt.Errorf("%w: expires", ErrMalformedSignatureParameter)
			}

			p.expires = value
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
