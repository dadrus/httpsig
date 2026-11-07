package httpsig

import (
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSerializer(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		params *httpsfv.Params
		req    bool
		assert func(t *testing.T, s serializer, err error)
	}{
		{
			uc: "req parameter not allowed for requests",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("req", true)

				return params
			}(),
			req: true,
			assert: func(t *testing.T, _ serializer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, "'req' parameter")
			},
		},
		{
			uc: "strict encoding serializer",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("sf", true)

				return params
			}(),
			assert: func(t *testing.T, s serializer, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &strictSerializer{}, s)
			},
		},
		{
			uc: "structured field serializer",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("key", "foo")

				return params
			}(),
			assert: func(t *testing.T, s serializer, err error) {
				t.Helper()

				require.NoError(t, err)

				ser, ok := s.(*strictSerializer)
				require.True(t, ok)
				assert.Equal(t, "foo", ser.key)
			},
		},
		{
			uc: "byte sequence serializer",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("bs", true)

				return params
			}(),
			assert: func(t *testing.T, s serializer, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &byteSequenceSerializer{}, s)
			},
		},
		{
			uc:     "raw serializer",
			params: httpsfv.NewParams(),
			assert: func(t *testing.T, s serializer, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.IsType(t, &rawSerializer{}, s)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			s, err := newSerializer(tc.params, tc.req)

			tc.assert(t, s, err)
		})
	}
}

func TestRawSerialization(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		input       []string
		result      []string
		errContains string
	}{
		{
			uc:     "dictionary field",
			input:  []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
			result: []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
		},
		{
			uc:     "list field with surrounding whitespace",
			input:  []string{" value,   with, lots, of,  commas, and,     spaces"},
			result: []string{"value,   with, lots, of,  commas, and,     spaces"},
		},
		{
			uc:     "strip HTTP whitespace from each field value",
			input:  []string{" \t alpha \t", "\tbeta  "},
			result: []string{"alpha", "beta"},
		},
		{
			uc:     "empty field value",
			input:  []string{"", " \t "},
			result: []string{"", ""},
		},
		{
			uc:     "preserve internal whitespace and commas",
			input:  []string{"alpha \t beta,  gamma"},
			result: []string{"alpha \t beta,  gamma"},
		},
		{
			uc:     "unfold obsolete line folding with preceding whitespace",
			input:  []string{"alpha \t\r\n\t beta"},
			result: []string{"alpha beta"},
		},
		{
			uc:          "reject leading obsolete line folding",
			input:       []string{"\r\n value"},
			errContains: "invalid HTTP field value",
		},
		{
			uc:          "reject leading obsolete line folding after whitespace",
			input:       []string{" \t\r\n value"},
			errContains: "invalid HTTP field value",
		},
		{
			uc:          "reject non-ASCII UTF-8",
			input:       []string{"caf\u00e9"},
			errContains: "non-ASCII",
		},
		{
			uc:          "reject non-ASCII octet",
			input:       []string{"\xff"},
			errContains: "non-ASCII",
		},
		{
			uc:          "reject bare newline",
			input:       []string{"alpha\nbeta"},
			errContains: "invalid HTTP field value",
		},
		{
			uc:          "reject NUL",
			input:       []string{"alpha\x00beta"},
			errContains: "invalid HTTP field value",
		},
		{
			uc:          "reject other ASCII control characters",
			input:       []string{"alpha\x01beta"},
			errContains: "invalid HTTP field value",
		},
		{
			uc:          "reject DEL",
			input:       []string{"alpha\x7fbeta"},
			errContains: "invalid HTTP field value",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			params := httpsfv.NewParams()

			s, err := newSerializer(params, false)
			require.NoError(t, err)

			result, err := s.serialize(tc.input)
			if tc.errContains != "" {
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, tc.errContains)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.result, result)
		})
	}
}

func TestByteSequenceSerialization(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		input  []string
		result []string
	}{
		{
			uc:     "two fields",
			input:  []string{"value, with, lots", "of, commas"},
			result: []string{":dmFsdWUsIHdpdGgsIGxvdHM=:", ":b2YsIGNvbW1hcw==:"},
		},
		{
			uc:     "single field",
			input:  []string{"value, with, lots, of, commas"},
			result: []string{":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:"},
		},
		{
			uc:     "preserve internal spaces and commas",
			input:  []string{"foo ,  bar"},
			result: []string{":Zm9vICwgIGJhcg==:"},
		},
		{
			uc:     "preserve internal tabs",
			input:  []string{"alpha\tbeta"},
			result: []string{":YWxwaGEJYmV0YQ==:"},
		},
		{
			uc:     "strip surrounding HTTP whitespace",
			input:  []string{"\t alpha \t"},
			result: []string{":YWxwaGE=:"},
		},
		{
			uc:     "unfold obsolete line folding",
			input:  []string{"hello\r\n \tworld"},
			result: []string{":aGVsbG8gd29ybGQ=:"},
		},
		{
			uc:     "unfold obsolete line folding with preceding whitespace",
			input:  []string{"hello  \r\n \tworld"},
			result: []string{":aGVsbG8gd29ybGQ=:"},
		},
		{
			uc:     "preserve non-ASCII whitespace bytes",
			input:  []string{"\u00a0alpha"},
			result: []string{":wqBhbHBoYQ==:"},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("bs", true)

			s, err := newSerializer(params, false)
			require.NoError(t, err)

			result, err := s.serialize(tc.input)
			require.NoError(t, err)

			assert.Equal(t, tc.result, result)
		})
	}
}

func TestStrictEncodingSerialization(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		input  []string
		result []string
		err    bool
	}{
		{
			uc:     "dictionary field",
			input:  []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
			result: []string{"a=1, b=2;x=1;y=2, c=(a b c)"},
		},
		{
			uc:     "field with lots of comas and spaces",
			input:  []string{" value,   with, lots, of,  commas, and,     spaces"},
			result: []string{"value, with, lots, of, commas, and, spaces"},
		},
		{
			uc:     "list field",
			input:  []string{"(a   b c  d  e f     g)"},
			result: []string{"(a b c d e f g)"},
		},
		{
			uc:     "item field",
			input:  []string{"foo; bar=baz"},
			result: []string{"foo;bar=baz"},
		},
		{
			uc:     "bare item field",
			input:  []string{" 1 "},
			result: []string{"1"},
		},
		{
			uc:    "list field",
			input: []string{"[a b c]"},
			err:   true,
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("sf", true)

			s, err := newSerializer(params, false)
			require.NoError(t, err)

			result, err := s.serialize(tc.input)
			if tc.err {
				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.result, result)
			}
		})
	}
}

func TestStructuredFieldSerialization(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		input  []string
		key    string
		result []string
		err    bool
	}{
		"integer member":               {input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "a", result: []string{"1"}},
		"member with parameters":       {input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "b", result: []string{"2;x=1;y=2"}},
		"inner list member":            {input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "c", result: []string{"(a b c)"}},
		"boolean member in dictionary": {input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "d", result: []string{"?1"}},
		"single bare boolean member":   {input: []string{"a"}, key: "a", result: []string{"?1"}},
		"bare boolean with parameters": {input: []string{"a;x=1"}, key: "a", result: []string{"?1;x=1"}},
		"missing dictionary member":    {input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "e", err: true},
		"non-dictionary field":         {input: []string{"(a b c)"}, key: "a", err: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			params.Add("key", tc.key)

			s, err := newSerializer(params, false)
			require.NoError(t, err)

			result, err := s.serialize(tc.input)

			if tc.err {
				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.result, result)
			}
		})
	}
}
