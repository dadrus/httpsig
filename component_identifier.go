package httpsig

import (
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

	canonicalizer, err := canonicalizerFor(name)
	if err != nil {
		return nil, err
	}

	return &componentIdentifier{Item: item, c: canonicalizer}, nil
}

// optionValue returns the identifier in the form accepted by WithComponents.
// The name stays quoted if removing the quotes would change its meaning.
func (c *componentIdentifier) optionValue() (string, error) {
	marshalled, err := httpsfv.Marshal(c.Item)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidComponentIdentifier, err)
	}

	name := c.Value.(string) //nolint: forcetypeassert
	if strings.ContainsAny(name, `";\`) {
		return marshalled, nil
	}

	return name + strings.TrimPrefix(marshalled, `"`+name+`"`), nil
}

func (c *componentIdentifier) createComponent(msg *Message) (component, error) {
	values, err := c.c.canonicalize(msg, c.Params)
	if err != nil {
		return component{}, err
	}

	return component{key: c, value: values}, nil
}
