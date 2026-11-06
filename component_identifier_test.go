package httpsig

import (
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuoteIdentifierName(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		given  string
		expect string
	}{
		"name already quoted":                {given: `"@method";req,key=val`, expect: `"@method";req,key=val`},
		"name not quoted, without parameter": {given: `@method`, expect: `"@method"`},
		"name not quoted, with parameter":    {given: `@method;req,key=val`, expect: `"@method";req,key=val`},
	} {
		t.Run(uc, func(t *testing.T) {
			res := quoteIdentifierName(tc.given)
			assert.Equal(t, tc.expect, res)
		})
	}
}

func TestToComponentIdentifiers(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifiers []string
		assert      func(t *testing.T, ci []*componentIdentifier, err error)
	}{
		"invalid identifier definition": {
			identifiers: []string{"foo;#"},
			assert: func(t *testing.T, _ []*componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
			},
		},
		"unknown identifier": {
			identifiers: []string{"@foo"},
			assert: func(t *testing.T, _ []*componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		"preserving structured field parameter types": {
			identifiers: []string{`x-test;string="abc";token=abc;bytes=:AQID:`},
			assert: func(t *testing.T, ci []*componentIdentifier, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ci, 1)

				stringValue, ok := ci[0].Params.Get("string")
				require.True(t, ok)
				assert.Equal(t, "abc", stringValue)

				tokenValue, ok := ci[0].Params.Get("token")
				require.True(t, ok)
				assert.Equal(t, httpsfv.Token("abc"), tokenValue)

				bytesValue, ok := ci[0].Params.Get("bytes")
				require.True(t, ok)
				assert.Equal(t, []byte{1, 2, 3}, bytesValue)

			},
		},
		"valid": {
			identifiers: []string{"@method;foo=bar", "@status", `@query-param;name="Pet"`},
			assert: func(t *testing.T, ci []*componentIdentifier, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ci, 3)

				assert.Equal(t, "@method", ci[0].Value.(string))
				res, ok := ci[0].Params.Get("foo")
				require.True(t, ok)
				require.Equal(t, httpsfv.Token("bar"), res)
				assert.NotNil(t, ci[0].c)

				assert.Equal(t, "@status", ci[1].Value.(string))
				assert.Empty(t, ci[1].Params.Names())
				assert.NotNil(t, ci[1].c)

				assert.Equal(t, "@query-param", ci[2].Value.(string))
				res, ok = ci[2].Params.Get("name")
				require.True(t, ok)
				require.Equal(t, "Pet", res.(string))
				assert.NotNil(t, ci[2].c)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			res, err := toComponentIdentifiers(tc.identifiers)

			tc.assert(t, res, err)
		})
	}
}

func TestNewComponentIdentifier(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		item   httpsfv.Item
		assert func(t *testing.T, ci *componentIdentifier, err error)
	}{
		"non-string component name": {
			item: httpsfv.NewItem(int64(42)),
			assert: func(t *testing.T, ci *componentIdentifier, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, ci)
			},
		},
		"invalid": {
			item: httpsfv.NewItem("@foo"),
			assert: func(t *testing.T, _ *componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		"uppercase component name": {
			item: httpsfv.NewItem("Content-Type"),
			assert: func(t *testing.T, ci *componentIdentifier, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, ci)
			},
		},
		"valid": {
			item: func() httpsfv.Item {
				item := httpsfv.NewItem("@method")
				item.Params.Add("foo", []byte("bar"))

				return item
			}(),
			assert: func(t *testing.T, ci *componentIdentifier, err error) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, ci.c)

				val, ok := ci.Params.Get("foo")
				require.True(t, ok)
				assert.Equal(t, []byte("bar"), val)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			ci, err := newComponentIdentifier(tc.item)

			tc.assert(t, ci, err)
		})
	}
}

func TestComponentIdentifierEqual(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		first  string
		second string
		equal  bool
	}{
		"same identifier with reordered parameters": {
			first:  `x-test;key="foo";sf`,
			second: `x-test;sf;key="foo"`,
			equal:  true,
		},
		"different names": {
			first:  `x-first`,
			second: `x-second`,
		},
		"different parameter names": {
			first:  `x-test;first="foo"`,
			second: `x-test;second="foo"`,
		},
		"different parameter counts": {
			first:  `x-test;req`,
			second: `x-test`,
		},
		"different parameter values": {
			first:  `x-test;key="foo"`,
			second: `x-test;key="bar"`,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			identifiers, err := toComponentIdentifiers([]string{tc.first, tc.second})
			require.NoError(t, err)

			assert.Equal(t, tc.equal, identifiers[0].equal(identifiers[1]))
		})
	}
}

func TestEqualComponentParameterValues(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		actual   any
		expected any
		equal    bool
	}{
		"equal byte sequences": {
			actual:   []byte{1, 2, 3},
			expected: []byte{1, 2, 3},
			equal:    true,
		},
		"different byte sequences": {
			actual:   []byte{1, 2, 4},
			expected: []byte{1, 2, 3},
		},
		"non-byte value against byte sequence": {
			actual:   "foo",
			expected: []byte{1, 2, 3},
		},
		"equal scalar values": {
			actual:   int64(42),
			expected: int64(42),
			equal:    true,
		},
		"different scalar types": {
			actual:   httpsfv.Token("foo"),
			expected: "foo",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.equal, equalComponentParameterValues(tc.actual, tc.expected))
		})
	}
}

func TestComponentIdentifierCreateComponent(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		item httpsfv.Item
		msg  *Message
		err  error
	}{
		"with error during canonicalization": {
			item: func() httpsfv.Item {
				item := httpsfv.NewItem("@method")
				item.Params.Add("req", true)

				return item
			}(),
			msg: &Message{Method: "GET", IsRequest: true},
			err: ErrCanonicalization,
		},
		"successful": {
			item: httpsfv.NewItem("@method"),
			msg:  &Message{Method: "POST", IsRequest: true},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			ci, err := newComponentIdentifier(tc.item)
			require.NoError(t, err)

			c, err := ci.createComponent(tc.msg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, c)
				assert.Equal(t, ci, c.key)
				assert.NotEmpty(t, c.value)
			}
		})
	}
}
