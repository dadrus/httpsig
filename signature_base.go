package httpsig

import (
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

type serializedComponent struct {
	identifier string
	value      string
}

// The entries correspond to input.identifiers by index. Signature parameters are separate.
type signatureBase struct {
	input           *signatureInput
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
		input:           si,
		entries:         make([]serializedComponent, 0, len(si.identifiers)),
		signatureParams: marshalledSigParams,
	}
	seen := make(map[string]struct{}, len(si.identifiers))

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

		if _, ok := seen[identifier]; ok {
			return signatureBase{}, fmt.Errorf("%w: duplicate component identifier %s", ErrMalformedData, identifier)
		}

		seen[identifier] = struct{}{}

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

	for i, item := range s.entries {
		name := s.input.identifiers[i].Value.(string) // nolint: forcetypeassert

		// Remove quotes around the component name,
		// preserving identifier parameters.
		prefix := `"` + name + `"`
		key := name + strings.TrimPrefix(item.identifier, prefix)

		result[key] = item.value
	}

	return result
}
