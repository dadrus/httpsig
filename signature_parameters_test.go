package httpsig

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureParameters(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		created     time.Time
		expires     time.Time
		nonce       string
		keyID       string
		tag         string
		algorithm   SignatureAlgorithm
		identifiers []*componentIdentifier
		assert      func(t *testing.T, params *signatureParameters)
	}{
		{
			uc: "without any parameters",
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			created: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				expCreated := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

				require.NotNil(t, params)
				assert.Equal(t, expCreated, params.created)
				assert.Equal(t, time.Time{}, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Created)})
				created, ok := params.Params.Get(string(Created))
				require.True(t, ok)
				assert.Equal(t, expCreated.Unix(), created)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:      "with expires only",
			expires: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				expExpires := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, expExpires, params.expires)
				assert.Empty(t, params.nonce)
				assert.Empty(t, params.keyID)
				assert.Empty(t, params.tag)
				assert.Empty(t, params.alg)
				assert.Empty(t, params.identifiers)
				require.NotNil(t, params.Params)
				assert.ElementsMatch(t, params.Params.Names(), []string{string(Expires)})
				expires, ok := params.Params.Get(string(Expires))
				require.True(t, ok)
				assert.Equal(t, expExpires.Unix(), expires)
				assert.Empty(t, params.Items)
			},
		},
		{
			uc:    "with nonce only",
			nonce: "test",
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
			uc:        "with everything specified",
			created:   time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
			expires:   time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
			nonce:     "nonce",
			keyID:     "key-id",
			tag:       "tag",
			algorithm: RsaPkcs1v15Sha512,
			identifiers: []*componentIdentifier{{
				Item: httpsfv.Item{Value: "test"},
			}},
			assert: func(t *testing.T, params *signatureParameters) {
				t.Helper()

				expCreated := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
				expExpires := time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

				require.NotNil(t, params)
				assert.Equal(t, expCreated, params.created)
				assert.Equal(t, expExpires, params.expires)
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
				assert.Equal(t, expCreated.Unix(), created)

				expires, ok := params.Params.Get(string(Expires))
				require.True(t, ok)
				assert.Equal(t, expExpires.Unix(), expires)

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
			params := newSignatureParameters(tc.created, tc.expires, tc.nonce, tc.keyID, tc.tag, tc.algorithm, tc.identifiers)

			tc.assert(t, params)
		})
	}
}

func TestSignatureParametersFromInnerList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		list   httpsfv.InnerList
		assert func(t *testing.T, err error, params *signatureParameters)
	}{
		{
			uc: "failing create component identifier",
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{{Value: "@test"}},
			},
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, _ *signatureParameters) {
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
			assert: func(t *testing.T, err error, params *signatureParameters) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, params)
				assert.Equal(t, time.Time{}, params.created)
				assert.Equal(t, time.Time{}, params.expires)
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
					params.Add(string(Created), time.Now().Unix())
					params.Add(string(Expires), time.Now().Add(5*time.Second).Unix())
					params.Add(string(Nonce), "nonce")
					params.Add(string(Tag), "tag")
					params.Add(string(Alg), string(RsaPssSha384))
					params.Add(string(KeyID), "test")

					return params
				}(),
			},
			assert: func(t *testing.T, err error, params *signatureParameters) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, params)

				assert.GreaterOrEqual(t, time.Now(), params.created)
				assert.Equal(t, time.UTC, params.created.Location())
				assert.GreaterOrEqual(t, time.Now().Add(5*time.Second), params.expires)
				assert.Equal(t, time.UTC, params.expires.Location())
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
			var params signatureParameters

			err := params.fromInnerList(tc.list)

			tc.assert(t, err, &params)
		})
	}
}

func TestSignatureParametersToSignatureBase(t *testing.T) {
	t.Parallel()

	// test is based on the non-normative example from
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-creating-the-signature-base

	reqURL, err := url.Parse("http://example.com/foo?param=Value&Pet=dog")
	require.NoError(t, err)

	msg := &Message{
		Method:    "POST",
		Authority: "example.com",
		URL:       reqURL,
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
			"Content-Length": []string{"18"},
		},
		StatusCode: 0,
		IsRequest:  true,
	}

	expectedSigBase := `"@method": POST
"@authority": example.com
"@path": /foo
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"content-type": application/json
"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"`

	identifiers, err := toComponentIdentifiers([]string{
		"@method", "@authority", "@path", "content-digest", "content-length", "content-type",
	})
	require.NoError(t, err)

	keyID := "test-key-rsa-pss"
	created, err := time.Parse(time.RFC1123, "Tue, 20 Apr 2021 02:07:53 GMT")
	require.NoError(t, err)

	params := newSignatureParameters(created, time.Time{}, "", keyID, "", "", identifiers)

	sigBase, err := params.toSignatureBase(msg)
	require.NoError(t, err)

	assert.Equal(t, expectedSigBase, string(sigBase))
}

func TestSignatureParametersAssert(t *testing.T) {
	now := time.Now().UTC()

	for _, tc := range []struct {
		uc                string
		params            httpsfv.InnerList
		validityTolerance time.Duration
		validityMaxAge    time.Duration
		expAlg            SignatureAlgorithm
		expIdentifiers    []string
		configure         func(t *testing.T, nc *NonceCheckerMock)
		assert            func(t *testing.T, err error)
	}{
		{
			uc: "replay attack",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Nonce), "test")

					return params
				}(),
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "test").Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "nonce validation failed")
			},
		},
		{
			uc: "signature algorithm mismatch",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Alg), string(RsaPssSha512))

					return params
				}(),
			},
			expAlg: EcdsaP256Sha256,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "key algorithm rsa-pss-sha512 does not match signature algorithm ecdsa-p256-sha256")
			},
		},
		{
			uc: "signature expired, no tolerance specified",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "expired")
			},
		},
		{
			uc: "signature is still valid with specified tolerance",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			validityTolerance: 3 * time.Second,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature is valid if expires in the future",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			validityTolerance: 2 * time.Second,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature not yet valid, no tolerance specified",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "not yet valid")
			},
		},
		{
			uc: "signature already valid with specified tolerance",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			validityTolerance: 3 * time.Second,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature is valid if created in the past",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			validityMaxAge: 30 * time.Second,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature too old",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "too old")
			},
		},
		{
			uc:             "expected component identifier missing",
			params:         httpsfv.InnerList{Params: httpsfv.NewParams()},
			expIdentifiers: []string{"@method;req", "@authority"},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, `"@method";req, "@authority"`)
			},
		},
		{
			uc: "successful assertion with all possible parameters",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-3*time.Second).Unix())
					params.Add(string(Expires), now.Add(3*time.Second).Unix())
					params.Add(string(Alg), string(EcdsaP256Sha256))
					params.Add(string(KeyID), "test")
					params.Add(string(Nonce), "foo")
					params.Add(string(Tag), "test")

					return params
				}(),
				Items: []httpsfv.Item{
					httpsfv.NewItem("@method"),
					httpsfv.NewItem("@authority"),
				},
			},
			expIdentifiers: []string{"@authority", "@method"},
			expAlg:         EcdsaP256Sha256,
			validityMaxAge: 5 * time.Second,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, "foo").Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			msg := &Message{Context: context.TODO()}

			expIdentifiers, err := toComponentIdentifiers(tc.expIdentifiers)
			require.NoError(t, err)

			var params signatureParameters

			err = params.fromInnerList(tc.params)
			require.NoError(t, err)

			nc := NewNonceCheckerMock(t)
			tc.configure(t, nc)

			err = params.assert(msg, false, false, tc.expAlg, expIdentifiers, tc.validityTolerance, tc.validityMaxAge, nc)

			tc.assert(t, err)
		})
	}
}
