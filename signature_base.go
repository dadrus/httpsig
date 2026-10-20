package httpsig

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

type signatureBase []component

func newSignatureBase(si *signatureInput, msg *Message) (signatureBase, error) {
	marshalledSigParams, err := httpsfv.Marshal(si.value)
	if err != nil {
		return nil, err
	}

	sigBase := make(signatureBase, 0, len(si.identifiers)+1)
	seen := make(map[string]struct{}, len(si.identifiers))

	for _, ci := range si.identifiers {
		identifier, err := httpsfv.Marshal(ci.Item)
		if err != nil {
			return nil, err
		}

		if _, ok := seen[identifier]; ok {
			return nil, fmt.Errorf("%w: duplicate component identifier %s", ErrMalformedData, identifier)
		}

		seen[identifier] = struct{}{}

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

	return sigBase, nil
}

func (s signatureBase) marshal() ([]byte, error) {
	var buf bytes.Buffer

	for i, item := range s {
		marshalledKey, err := httpsfv.Marshal(item.key.Item)
		if err != nil {
			return nil, err
		}

		if i > 0 {
			buf.WriteByte('\n')
		}

		buf.WriteString(marshalledKey)
		buf.WriteString(": ")
		buf.WriteString(item.canonicalValue())
	}

	return buf.Bytes(), nil
}

func (s signatureBase) components() (map[string]string, error) {
	result := make(map[string]string, len(s))

	for _, component := range s {
		name := component.key.Value.(string) // nolint: forcetypeassert

		if name == "@signature-params" {
			continue
		}

		identifier, err := httpsfv.Marshal(component.key.Item)
		if err != nil {
			return nil, err
		}

		// Remove quotes around the component name,
		// preserving identifier parameters.
		prefix := `"` + name + `"`
		key := name + strings.TrimPrefix(identifier, prefix)

		result[key] = component.canonicalValue()
	}

	return result, nil
}
