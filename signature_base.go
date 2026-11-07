package httpsig

import (
	"fmt"
	"slices"

	"github.com/dunglas/httpsfv"
)

type serializedComponent struct {
	identifier string
	value      string
}

// The entries preserve the covered component order. Signature parameters are separate.
type signatureBase struct {
	entries         []serializedComponent
	signatureParams string
}

func newSignatureBase(msg *Message, si *signatureInput, prepared []string) (signatureBase, error) {
	if prepared != nil && len(prepared) != len(si.identifiers) {
		return signatureBase{}, fmt.Errorf("%w: mismatched serialized component identifiers", ErrMalformedData)
	}

	marshalledSigParams, err := httpsfv.Marshal(si.value)
	if err != nil {
		return signatureBase{}, err
	}

	sigBase := signatureBase{
		entries:         make([]serializedComponent, 0, len(si.identifiers)),
		signatureParams: marshalledSigParams,
	}

	for i, ci := range si.identifiers {
		var identifier string
		if prepared == nil {
			identifier, err = httpsfv.Marshal(ci.Item)
			if err != nil {
				return signatureBase{}, err
			}
		} else {
			identifier = prepared[i]
		}

		if slices.ContainsFunc(si.identifiers[:i], ci.equal) {
			return signatureBase{}, fmt.Errorf("%w: duplicate component identifier %s", ErrMalformedData, identifier)
		}

		comp, err := ci.createComponent(msg)
		if err != nil {
			return signatureBase{}, err
		}

		sigBase.entries = append(sigBase.entries, serializedComponent{
			identifier: identifier,
			value:      comp.canonicalValue(),
		})
	}

	return sigBase, nil
}

func (s signatureBase) marshal() []byte {
	// calculate size
	size := 0
	for i, item := range s.entries {
		size += len(item.identifier) + len(": ") + len(item.value)
		if i > 0 {
			size++
		}
	}

	if s.signatureParams != "" {
		size += len(`"@signature-params": `) + len(s.signatureParams)
		if len(s.entries) > 0 {
			size++
		}
	}

	if size == 0 {
		return nil
	}

	// do the actual marshalling
	buf := make([]byte, 0, size)

	for i, item := range s.entries {
		if i > 0 {
			buf = append(buf, '\n')
		}

		buf = append(buf, item.identifier...)
		buf = append(buf, ':', ' ')
		buf = append(buf, item.value...)
	}

	if s.signatureParams != "" {
		if len(s.entries) > 0 {
			buf = append(buf, '\n')
		}

		buf = append(buf, `"@signature-params": `...)
		buf = append(buf, s.signatureParams...)
	}

	return buf
}

func (s signatureBase) components() map[string]string {
	result := make(map[string]string, len(s.entries))

	for _, item := range s.entries {
		result[item.identifier] = item.value
	}

	return result
}
