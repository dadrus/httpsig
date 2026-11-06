package httpsig

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/dunglas/httpsfv"
)

func quoteIdentifierName(input string) string {
	// nothing to do if already quoted
	if strings.HasPrefix(input, `"`) {
		return input
	}

	// try to split the structured field
	parts := strings.Split(input, ";")
	name, rest := parts[0], parts[1:]

	// always quote the name
	identifier := "\"" + name + "\""

	if len(rest) == 0 {
		return identifier
	}

	// just add the rest
	return identifier + ";" + strings.Join(rest, ";")
}

type componentIdentifier struct {
	httpsfv.Item

	c canonicalizer
}

func toComponentIdentifiers(identifiers []string) ([]*componentIdentifier, error) {
	cis := make([]*componentIdentifier, 0, len(identifiers))

	for _, identifier := range identifiers {
		item, err := httpsfv.UnmarshalItem([]string{quoteIdentifierName(identifier)})
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidComponentIdentifier, identifiers, err)
		}

		id, err := newComponentIdentifier(item)
		if err != nil {
			return nil, err
		}

		cis = append(cis, id)
	}

	return cis, nil
}

func newComponentIdentifier(item httpsfv.Item) (*componentIdentifier, error) {
	name, ok := item.Value.(string)
	if !ok {
		return nil, fmt.Errorf("%w: component name must be a string", ErrInvalidComponentIdentifier)
	}

	if name != strings.ToLower(name) {
		return nil, fmt.Errorf("%w: component name %q must be lowercase", ErrInvalidComponentIdentifier, name)
	}

	canonicalizer, err := canonicalizerFor(name, item.Params)
	if err != nil {
		return nil, err
	}

	return &componentIdentifier{Item: item, c: canonicalizer}, nil
}

// equal reports whether two component identifiers have the same name and
// parameters, regardless of parameter order.
func (c *componentIdentifier) equal(other *componentIdentifier) bool {
	if c.Value != other.Value || len(c.Params.Names()) != len(other.Params.Names()) {
		return false
	}

	for _, name := range c.Params.Names() {
		actual, present := other.Params.Get(name)
		expected, _ := c.Params.Get(name)

		if !present || !equalComponentParameterValues(actual, expected) {
			return false
		}
	}

	return true
}

func (c *componentIdentifier) createComponent(msg *Message) (component, error) {
	values, err := c.c.canonicalize(msg, c.Params)
	if err != nil {
		return component{}, err
	}

	return component{key: c, value: values}, nil
}

func equalComponentParameterValues(actual, expected any) bool {
	if expectedBytes, ok := expected.([]byte); ok {
		actualBytes, ok := actual.([]byte)

		return ok && bytes.Equal(actualBytes, expectedBytes)
	}

	return actual == expected
}
