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
			uc: "message trailers are not supported",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("tr", true)

				return params
			}(),
			assert: func(t *testing.T, _ serializer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, "message trailers are not supported")
			},
		},
		{
			uc: "sf and bs serialization are mutually exclusive",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("bs", true)
				params.Add("sf", true)

				return params
			}(),
			assert: func(t *testing.T, _ serializer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, "cannot have both")
			},
		},
		{
			uc: "key and bs serialization are mutually exclusive",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("bs", true)
				params.Add("key", true)

				return params
			}(),
			assert: func(t *testing.T, _ serializer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, "cannot have both")
			},
		},
		{
			uc: "dictionary structured field key must be a string",
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("key", 1)

				return params
			}(),
			assert: func(t *testing.T, _ serializer, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, errSerialization)
				require.ErrorContains(t, err, "must be a string")
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
		uc     string
		input  []string
		result []string
	}{
		{
			uc:     "dictionary field",
			input:  []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
			result: []string{"a=1,    b=2;x=1;y=2,   c=(a   b   c)"},
		},
		{
			uc:     "list field",
			input:  []string{" value,   with, lots, of,  commas, and,     spaces"},
			result: []string{" value,   with, lots, of,  commas, and,     spaces"},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			params := httpsfv.NewParams()

			s, err := newSerializer(params, false)
			require.NoError(t, err)

			result, err := s.serialize(tc.input)
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

	for _, tc := range []struct {
		input  []string
		key    string
		result []string
		err    bool
	}{
		{input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "a", result: []string{"1"}},
		{input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "b", result: []string{"2;x=1;y=2"}},
		{input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "c", result: []string{"(a b c)"}},
		{input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "d", result: []string{"?1"}},
		{input: []string{"  a=1, b=2;x=1;y=2, c=(a   b    c), d"}, key: "e", err: true},
		{input: []string{"(a b c)"}, key: "a", err: true},
	} {
		t.Run("key="+tc.key, func(t *testing.T) {
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
