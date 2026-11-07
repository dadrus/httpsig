package httpsig

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dunglas/httpsfv"
)

var errSerialization = errors.New("serialization error")

//nolint:gochecknoglobals
var fieldValueObsFold = regexp.MustCompile("[ \t]*\r\n[ \t]+")

type serializer interface {
	serialize(v []string) ([]string, error)
}

func newSerializer(params *httpsfv.Params, isRequest bool) (serializer, error) {
	if _, hasReqParam := params.Get("req"); hasReqParam && isRequest {
		return nil, fmt.Errorf("%w: 'req' parameter not valid for requests",
			errSerialization)
	}

	_, isBs := params.Get("bs")
	_, isSf := params.Get("sf")
	keyParam, isKey := params.Get("key")
	key, _ := keyParam.(string) // validated by canonicalizerFor

	switch {
	case isSf || isKey:
		return &strictSerializer{key: key}, nil
	case isBs:
		return &byteSequenceSerializer{}, nil
	default:
		return &rawSerializer{}, nil
	}
}

type rawSerializer struct{}

//nolint:cyclop
func (s *rawSerializer) serialize(values []string) ([]string, error) {
	var normalized []string

	for i, sv := range values {
		// RFC 9421, Sections 2.1 and 2.5: normalize field values and
		// ensure that the signature base contains only ASCII.
		value := strings.Trim(sv, " \t")
		if strings.HasPrefix(value, "\r\n") {
			return nil, fmt.Errorf("%w: invalid HTTP field value", errSerialization)
		}

		if strings.Contains(value, "\r\n") {
			value = fieldValueObsFold.ReplaceAllString(value, " ")
		}

		for j := range len(value) {
			ch := value[j]
			if ch >= 0x80 { //nolint:mnd
				return nil, fmt.Errorf("%w: non-ASCII HTTP field value (use 'bs' for binary values)", errSerialization)
			}

			if (ch < 0x20 && ch != '\t') || ch == 0x7f {
				return nil, fmt.Errorf("%w: invalid HTTP field value", errSerialization)
			}
		}

		if value != sv && normalized == nil {
			normalized = append([]string(nil), values...)
		}

		if normalized != nil {
			normalized[i] = value
		}
	}

	if normalized != nil {
		return normalized, nil
	}

	return values, nil
}

type byteSequenceSerializer struct{}

func (s *byteSequenceSerializer) serialize(v []string) ([]string, error) {
	encoded := make([]string, len(v))

	for i, sv := range v {
		// RFC 9421, Section 2.1.3: preserve field-value bytes except for
		// surrounding HTTP whitespace and obsolete line folding.
		value := strings.Trim(sv, " \t")
		value = fieldValueObsFold.ReplaceAllString(value, " ")
		item := httpsfv.NewItem([]byte(value))

		marshalled, err := httpsfv.Marshal(item)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSerialization, err)
		}

		encoded[i] = marshalled
	}

	return encoded, nil
}

type strictSerializer struct {
	key string
}

func (s *strictSerializer) serialize(values []string) ([]string, error) {
	var parsed httpsfv.StructuredFieldValue

	if len(s.key) != 0 {
		// The 'key' parameter requires dictionary parsing, even when the
		// field value could also be parsed as a list (e.g. a bare boolean member).
		dict, err := httpsfv.UnmarshalDictionary(values)
		if err != nil {
			return nil, fmt.Errorf("%w: unable to parse value as dictionary: %w", errSerialization, err)
		}

		val, ok := dict.Get(s.key)
		if !ok {
			return nil, fmt.Errorf("%w: unable to find key '%s' in structured field", errSerialization, s.key)
		}

		parsed = val
	} else {
		var err error

		parsed, err = s.parse(values)
		if err != nil {
			return nil, err
		}
	}

	marshalled, err := httpsfv.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSerialization, err)
	}

	return []string{marshalled}, nil
}

func (s *strictSerializer) parse(values []string) (httpsfv.StructuredFieldValue, error) {
	list, err := httpsfv.UnmarshalList(values)
	if err == nil {
		return list, nil
	}

	dict, err := httpsfv.UnmarshalDictionary(values)
	if err == nil {
		return dict, nil
	}

	item, err := httpsfv.UnmarshalItem(values)
	if err == nil {
		return item, nil
	}

	return nil, fmt.Errorf("%w: unable to parse structured header", errSerialization)
}
