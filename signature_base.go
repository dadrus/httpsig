package httpsig

import (
	"bytes"
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

func newSignatureBase(si *signatureInput, msg *Message) (signatureBase, error) {
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

	for _, ci := range si.identifiers {
		identifier, err := httpsfv.Marshal(ci.Item)
		if err != nil {
			return signatureBase{}, err
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

func (s signatureBase) marshal() ([]byte, error) {
	var buf bytes.Buffer

	for i, item := range s.entries {
		if i > 0 {
			buf.WriteByte('\n')
		}

		buf.WriteString(item.identifier)
		buf.WriteString(": ")
		buf.WriteString(item.value)
	}

	if s.signatureParams != "" {
		if len(s.entries) > 0 {
			buf.WriteByte('\n')
		}

		buf.WriteString(`"@signature-params": `)
		buf.WriteString(s.signatureParams)
	}

	return buf.Bytes(), nil
}

func (s signatureBase) components() (map[string]string, error) {
	result := make(map[string]string, len(s.entries))

	for i, item := range s.entries {
		name := s.input.identifiers[i].Value.(string) // nolint: forcetypeassert

		// Remove quotes around the component name,
		// preserving identifier parameters.
		prefix := `"` + name + `"`
		key := name + strings.TrimPrefix(item.identifier, prefix)

		result[key] = item.value
	}

	return result, nil
}
