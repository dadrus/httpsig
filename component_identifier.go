package httpsig

import (
	"encoding/base64"
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

func normaliseParams(params *httpsfv.Params) *httpsfv.Params {
	if len(params.Names()) == 0 {
		return params
	}

	ps := httpsfv.NewParams()

	for _, name := range params.Names() {
		value, _ := params.Get(name)

		if v, ok := value.([]byte); ok {
			encoded := base64.StdEncoding.EncodeToString(v)
			ps.Add(name, encoded)
		} else if v, ok := value.(httpsfv.Token); ok {
			ps.Add(name, string(v))
		} else {
			ps.Add(name, value)
		}
	}

	return ps
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
	// ok if panics
	name := strings.ToLower(item.Value.(string)) //nolint: forcetypeassert

	canonicalizer, err := canonicalizerFor(name)
	if err != nil {
		return nil, err
	}

	item.Params = normaliseParams(item.Params)

	return &componentIdentifier{Item: item, c: canonicalizer}, nil
}

func (c *componentIdentifier) createComponent(msg *Message) (component, error) {
	values, err := c.c.canonicalize(msg, c.Params)
	if err != nil {
		return component{}, err
	}

	return component{key: c, value: values}, nil
}
