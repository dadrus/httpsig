package httpsig

import (
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuoteIdentifierName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		given  string
		expect string
	}{
		{uc: "name already quoted", given: `"@method";req,key=val`, expect: `"@method";req,key=val`},
		{uc: "name not quoted, without parameter", given: `@method`, expect: `"@method"`},
		{uc: "name not quoted, with parameter", given: `@method;req,key=val`, expect: `"@method";req,key=val`},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			res := quoteIdentifierName(tc.given)
			assert.Equal(t, tc.expect, res)
		})
	}
}

func TestNormalizeParams(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		given  *httpsfv.Params
		expect *httpsfv.Params
	}{
		{
			uc:     "empty params",
			given:  httpsfv.NewParams(),
			expect: httpsfv.NewParams(),
		},
		{
			uc: "byte array params",
			given: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", []byte("test"))

				return params
			}(),
			expect: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", "dGVzdA==")

				return params
			}(),
		},
		{
			uc: "token params",
			given: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", httpsfv.Token("token"))

				return params
			}(),
			expect: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", "token")

				return params
			}(),
		},
		{
			uc: "bare item params",
			given: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", 1)

				return params
			}(),
			expect: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("test", 1)

				return params
			}(),
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			res := normaliseParams(tc.given)

			assert.Equal(t, tc.given.Names(), res.Names())

			for _, name := range res.Names() {
				resVal, ok := res.Get(name)
				assert.True(t, ok)

				expVal, ok := tc.expect.Get(name)
				assert.True(t, ok)

				assert.Equal(t, expVal, resVal)
			}
		})
	}
}

func TestToComponentIdentifiers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		identifiers []string
		assert      func(t *testing.T, ci []*componentIdentifier, err error)
	}{
		{
			uc:          "invalid identifier definition",
			identifiers: []string{"foo;#"},
			assert: func(t *testing.T, _ []*componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
			},
		},
		{
			uc:          "unknown identifier",
			identifiers: []string{"@foo"},
			assert: func(t *testing.T, _ []*componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		{
			uc:          "valid",
			identifiers: []string{"@method;foo=bar", "@status"},
			assert: func(t *testing.T, ci []*componentIdentifier, err error) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, ci, 2)

				assert.Equal(t, "@method", ci[0].Value.(string))
				res, ok := ci[0].Params.Get("foo")
				require.True(t, ok)
				require.Equal(t, "bar", res.(string))
				assert.NotNil(t, ci[0].c)

				assert.Equal(t, "@status", ci[1].Value.(string))
				assert.Empty(t, ci[1].Params.Names())
				assert.NotNil(t, ci[1].c)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			res, err := toComponentIdentifiers(tc.identifiers)

			tc.assert(t, res, err)
		})
	}
}

func TestNewComponentIdentifier(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		item   httpsfv.Item
		assert func(t *testing.T, ci *componentIdentifier, err error)
	}{
		{
			uc:   "invalid",
			item: httpsfv.NewItem("@foo"),
			assert: func(t *testing.T, _ *componentIdentifier, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		{
			uc: "valid",
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
				assert.Equal(t, "YmFy", val)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			ci, err := newComponentIdentifier(tc.item)

			tc.assert(t, ci, err)
		})
	}
}

func TestComponentIdentifierCreateComponent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc   string
		item httpsfv.Item
		msg  *Message
		err  error
	}{
		{
			uc: "with error during canonicalization",
			item: func() httpsfv.Item {
				item := httpsfv.NewItem("@method")
				item.Params.Add("req", true)

				return item
			}(),
			msg: &Message{Method: "GET", IsRequest: true},
			err: ErrCanonicalization,
		},
		{
			uc:   "with error during canonicalization",
			item: httpsfv.NewItem("@method"),
			msg:  &Message{Method: "POST", IsRequest: true},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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
