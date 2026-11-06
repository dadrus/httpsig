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
var byteSequenceObsFold = regexp.MustCompile("[ \t]*\r\n[ \t]+")

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

func (s *rawSerializer) serialize(v []string) ([]string, error) {
	return v, nil
}

type byteSequenceSerializer struct{}

func (s *byteSequenceSerializer) serialize(v []string) ([]string, error) {
	encoded := make([]string, len(v))

	for i, sv := range v {
		// RFC 9421, Section 2.1.3: preserve field-value bytes except for
		// surrounding HTTP whitespace and obsolete line folding.
		value := strings.Trim(sv, " \t")
		value = byteSequenceObsFold.ReplaceAllString(value, " ")
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

func (s *strictSerializer) serialize(v []string) ([]string, error) {
	// strict encoding of field
	parsed, err := s.parse(v)
	if err != nil {
		return nil, err
	}

	if len(s.key) != 0 {
		dict, ok := parsed.(*httpsfv.Dictionary)
		if !ok {
			return nil, fmt.Errorf("%w: unable to parse value as dictionary",
				errSerialization)
		}

		val, ok := dict.Get(s.key)
		if !ok {
			return nil, fmt.Errorf("%w: unable to find key '%s' in structured field", errSerialization, s.key)
		}

		marshalled, err := httpsfv.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSerialization, err)
		}

		return []string{marshalled}, nil
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
