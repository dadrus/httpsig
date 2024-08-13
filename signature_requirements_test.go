package httpsig

import (
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureRequirements(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		created     bool
		expires     bool
		nonce       string
		algorithm   SignatureAlgorithm
		keyID       string
		tag         string
		identifiers []*componentIdentifier
		assert      func(t *testing.T, params *signatureRequirements)
	}{
		{
			uc: "without any parameters",
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.Empty(t, params.Params.Names())
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:      "with created only",
			created: true,
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.True(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Created)})
				created, ok := params.Params.Get(string(Created))
				require.True(t, ok)
				assert.Equal(t, true, created)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:      "with expires only",
			expires: true,
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.True(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Expires)})
				expires, ok := params.Params.Get(string(Expires))
				require.True(t, ok)
				assert.Equal(t, true, expires)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:    "with nonce only",
			nonce: "test",
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Equal(t, "test", params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Nonce)})
				nonce, ok := params.Params.Get(string(Nonce))
				require.True(t, ok)
				assert.Equal(t, "test", nonce)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:    "with keyid only",
			keyID: "test",
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Equal(t, "test", params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(KeyID)})
				keyID, ok := params.Params.Get(string(KeyID))
				require.True(t, ok)
				assert.Equal(t, "test", keyID)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:  "with tag only",
			tag: "test",
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Equal(t, "test", params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Tag)})
				tag, ok := params.Params.Get(string(Tag))
				require.True(t, ok)
				assert.Equal(t, "test", tag)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:        "with algorithm only",
			algorithm: RsaPssSha384,
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Equal(t, RsaPssSha384, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Alg)})
				alg, ok := params.Params.Get(string(Alg))
				require.True(t, ok)
				assert.Equal(t, string(RsaPssSha384), alg)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc: "with identifiers only",
			identifiers: []*componentIdentifier{{
				Item: httpsfv.Item{Value: "test"},
			}},
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Len(t, params.identifiers, 1)
				require.NotNil(t, params.Params)
				assert.Empty(t, params.Params.Names())
				require.Len(t, params.Items, 1)
				assert.Equal(t, "test", params.Items[0].Value)
			},
		},
		{
			uc:          "with everything specified",
			created:     true,
			expires:     true,
			nonce:       "nonce",
			keyID:       "key-id",
			tag:         "tag",
			algorithm:   RsaPkcs1v15Sha512,
			identifiers: []*componentIdentifier{{Item: httpsfv.Item{Value: "test"}}},
			assert: func(t *testing.T, params *signatureRequirements) {
				t.Helper()

				require.NotNil(t, params)
				assert.True(t, params.created)
				assert.True(t, params.expires)
				assert.Equal(t, "nonce", params.nonce)
				assert.Equal(t, "key-id", params.keyID)
				assert.Equal(t, "tag", params.tag)
				assert.Equal(t, RsaPkcs1v15Sha512, params.alg)
				assert.Len(t, params.identifiers, 1)
				require.NotNil(t, params.Params)
				assert.Len(t, params.Params.Names(), 6)
				assert.ElementsMatch(t, params.Params.Names(), []string{
					string(Created), string(Expires), string(Nonce), string(KeyID), string(Tag), string(Alg),
				})

				created, ok := params.Params.Get(string(Created))
				require.True(t, ok)
				assert.Equal(t, true, created)

				expires, ok := params.Params.Get(string(Expires))
				require.True(t, ok)
				assert.Equal(t, true, expires)

				nonce, ok := params.Params.Get(string(Nonce))
				require.True(t, ok)
				assert.Equal(t, "nonce", nonce)

				keyID, ok := params.Params.Get(string(KeyID))
				require.True(t, ok)
				assert.Equal(t, "key-id", keyID)

				tag, ok := params.Params.Get(string(Tag))
				require.True(t, ok)
				assert.Equal(t, "tag", tag)

				alg, ok := params.Params.Get(string(Alg))
				require.True(t, ok)
				assert.Equal(t, string(RsaPkcs1v15Sha512), alg)

				require.Len(t, params.Items, 1)
				assert.Equal(t, "test", params.Items[0].Value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			params := newSignatureRequirements(tc.created, tc.expires, tc.tag, tc.nonce, tc.keyID, tc.algorithm, tc.identifiers)

			tc.assert(t, params)
		})
	}
}

func TestSignatureRequirementsFromInnerList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		list   httpsfv.InnerList
		assert func(t *testing.T, err error, params *signatureRequirements)
	}{
		{
			uc: "failing create component identifier",
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{{Value: "@test"}},
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.ErrorContains(t, err, "@test")
			},
		},
		{
			uc: "failing parsing created parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), "foo")

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "created")
			},
		},
		{
			uc: "failing parsing expires parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), "foo")

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "expires")
			},
		},
		{
			uc: "failing parsing keyid parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(KeyID), 1)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "keyid")
			},
		},
		{
			uc: "failing parsing alg parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Alg), 1)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "alg")
			},
		},
		{
			uc: "failing parsing nonce parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Nonce), 1)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "nonce")
			},
		},
		{
			uc: "failing parsing tag parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Tag), 1)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "tag")
			},
		},
		{
			uc: "failing parsing unknown parameter",
			list: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add("foo", 1)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, _ *signatureRequirements) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, "foo is unknown")
			},
		},
		{
			uc: "with identifiers only",
			list: httpsfv.InnerList{
				Items:  []httpsfv.Item{{Value: "test", Params: httpsfv.NewParams()}},
				Params: httpsfv.NewParams(),
			},
			assert: func(t *testing.T, err error, params *signatureRequirements) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, params)
				assert.False(t, params.created)
				assert.False(t, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Len(t, params.identifiers, 1)
				assert.Equal(t, "test", params.identifiers[0].Value)
			},
		},
		{
			uc: "with everything specified",
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{{Value: "test", Params: httpsfv.NewParams()}},
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), true)
					params.Add(string(Expires), true)
					params.Add(string(Nonce), "nonce")
					params.Add(string(Tag), "tag")
					params.Add(string(Alg), string(RsaPssSha384))
					params.Add(string(KeyID), "test")

					return params
				}(),
			},
			assert: func(t *testing.T, err error, params *signatureRequirements) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, params)

				assert.True(t, params.created)
				assert.True(t, params.expires)
				assert.Equal(t, "nonce", params.nonce)
				assert.Equal(t, "tag", params.tag)
				assert.Equal(t, RsaPssSha384, params.alg)
				assert.Equal(t, "test", params.keyID)
				assert.Len(t, params.identifiers, 1)
				assert.Equal(t, "test", params.identifiers[0].Value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var params signatureRequirements

			err := params.fromInnerList(tc.list)

			tc.assert(t, err, &params)
		})
	}
}
