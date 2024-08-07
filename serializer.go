package httpsig

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/dunglas/httpsfv"
)

var errSerialization = errors.New("serialization error")

type serializer interface {
	serialize(v []string) ([]string, error)
}

//nolint:cyclop
func newSerializer(params *httpsfv.Params, isRequest bool) (serializer, error) {
	var (
		key string
		ok  bool
	)

	if _, hasReqParam := params.Get("req"); hasReqParam && isRequest {
		return nil, fmt.Errorf("%w: 'req' parameter not valid for requests",
			errSerialization)
	}

	_, isBs := params.Get("bs")
	_, isSf := params.Get("sf")
	_, isTr := params.Get("tr")
	keyParam, isKey := params.Get("key")

	if isTr {
		return nil, fmt.Errorf("%w: message trailers are not supported", errSerialization)
	}

	if isBs && (isSf || isKey) {
		return nil, fmt.Errorf("%w: cannot have both 'bs' and 'sf'/'key' parameters",
			errSerialization)
	}

	if isKey {
		if key, ok = keyParam.(string); !ok {
			return nil, fmt.Errorf("%w: key parameter must be a string", errSerialization)
		}
	}

	switch {
	case isSf || isKey:
		return &strictSerializer{key: key}, nil
	case isBs:
		return &byteSequenceSerializer{regex: regexp.MustCompile(`\s+`)}, nil
	default:
		return &rawSerializer{}, nil
	}
}

type rawSerializer struct{}

func (s *rawSerializer) serialize(v []string) ([]string, error) {
	return v, nil
}

type byteSequenceSerializer struct {
	regex *regexp.Regexp
}

func (s *byteSequenceSerializer) serialize(v []string) ([]string, error) {
	encoded := make([]string, len(v))

	for i, sv := range v {
		values := strings.Split(sv, ",")
		for j, v := range values {
			values[j] = s.regex.ReplaceAllString(strings.TrimSpace(v), " ")
		}

		item := httpsfv.NewItem([]byte(strings.Join(values, ", ")))

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
