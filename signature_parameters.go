package httpsig

import (
	"fmt"
	"slices"
	"strings"
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

//nolint:cyclop
func (p *signatureParameters) assert(
	msg *Message,
	keyAlg SignatureAlgorithm,
	params []SignatureParameter,
	identifiers []*componentIdentifier,
	tolerance time.Duration,
	maxAge time.Duration,
	checker NonceChecker,
) error {
	if nonce, present := p.Params.Get(string(Nonce)); present {
		if err := checker.CheckNonce(msg.Context, nonce.(string)); err != nil { //nolint: forcetypeassert
			return fmt.Errorf("%w: nonce validation failed: %w", ErrParameter, err)
		}
	}

	if len(p.alg) != 0 && p.alg != keyAlg {
		return fmt.Errorf("%w: key algorithm %s does not match signature algorithm %s",
			ErrParameter, p.alg, keyAlg)
	}

	now := currentTime().UTC()

	if !p.expires.Equal(time.Time{}) && now.After(p.expires.Add(tolerance)) {
		return fmt.Errorf("%w: signature expired", ErrValidity)
	}

	if !p.created.Equal(time.Time{}) && now.Before(p.created.Add(-1*tolerance)) {
		return fmt.Errorf("%w: signature not yet valid", ErrValidity)
	}

	if !p.created.Equal(time.Time{}) && p.created.Add(maxAge).Before(now) {
		return fmt.Errorf("%w: signature too old", ErrValidity)
	}

	var (
		missingParams     []string
		missingComponents []string
	)

	for _, param := range params {
		if _, present := p.Params.Get(string(param)); !present {
			missingParams = append(missingParams, string(param))
		}
	}

	if len(missingParams) > 0 {
		return fmt.Errorf("%w: missing parameters: %s", ErrParameter, strings.Join(missingParams, ", "))
	}

	for _, expIdentifier := range identifiers {
		var found bool

		for _, identifier := range p.identifiers {
			if identifier.Item.Value == expIdentifier.Item.Value &&
				slices.Equal(identifier.Params.Names(), expIdentifier.Params.Names()) {
				found = true

				break
			}
		}

		if !found {
			res, _ := httpsfv.Marshal(expIdentifier)
			missingComponents = append(missingComponents, res)
		}
	}

	if len(missingComponents) > 0 {
		return fmt.Errorf("%w: missing component identifiers: %s",
			ErrParameter, strings.Join(missingComponents, ", "))
	}

	return nil
}
