package httpsig

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAcceptedSignature(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts   []AcceptSignatureOption
		assert func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		"no options provided": {
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.identifiers)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.keyID)
				assert.Empty(t, asb.signatureAlgorithm)
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.Nil(t, asb.nonceGetter)
				assert.Empty(t, asb.parameters)
				assert.Equal(t, "sig", asb.label)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{
					AlgorithmPreference{Algorithm: Sha256, Preference: 5}.String(),
					AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(),
				})
			},
		},
		"all possible options provided": {
			opts: []AcceptSignatureOption{
				WithSignatureAlgorithm(EcdsaP256Sha256),
				WithKeyID("test"),
				WithNonceGetter(&NonceGetterMock{}),
				WithLabel("foo"),
				WithComponents("@status", "content-digest;req"),
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 10}),
				WithTag("bar"),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
				WithParameter("audience", "service-a"),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, asb.wantContentDigest)
				assert.Len(t, asb.identifiers, 2)
				assert.Equal(t, "@status", asb.identifiers[0].Value)
				assert.Equal(t, "content-digest", asb.identifiers[1].Value)
				assert.Equal(t, "bar", asb.tag)
				assert.Equal(t, "test", asb.keyID)
				assert.Equal(t, EcdsaP256Sha256, asb.signatureAlgorithm)
				assert.False(t, asb.addCreatedTS)
				assert.False(t, asb.addExpiresTS)
				assert.Equal(t, &NonceGetterMock{}, asb.nonceGetter)
				assert.Equal(t, "foo", asb.label)
				assert.Equal(t, []parameterOption{{name: "audience", value: "service-a"}}, asb.parameters)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{
					AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(),
				})
			},
		},
		"invalid extension parameter": {
			opts: []AcceptSignatureOption{
				WithParameter("keyid", "reserved"),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Nil(t, asb)
			},
		},
		"option raises error": {
			opts: []AcceptSignatureOption{
				WithComponents("@foo"),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.Nil(t, asb)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			builder, err := NewAcceptSignature(tc.opts...)

			tc.assert(t, err, builder)
		})
	}
}

func TestAcceptSignatureBuilderBuild(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts      []AcceptSignatureOption
		buildOpts []AcceptSignatureBuildOption
		assert    func(t *testing.T, err error, hdr http.Header)
	}{
		"no nonce by default": {
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires`, hdr.Get(headerAcceptSignature))
			},
		},
		"explicit nonce at Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("nonce", "request-nonce"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires;nonce="request-nonce"`, hdr.Get(headerAcceptSignature))
			},
		},
		"explicit nonce overrides getter": {
			opts: []AcceptSignatureOption{
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) {
					return "", errors.New("getter must not be called")
				})),
			},
			buildOpts: []AcceptSignatureBuildOption{WithParameter("nonce", "requested")},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires;nonce="requested"`, hdr.Get(headerAcceptSignature))
			},
		},
		"empty nonce returned by getter is omitted": {
			opts: []AcceptSignatureOption{
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires`, hdr.Get(headerAcceptSignature))
			},
		},
		"non-string nonce in Build": {
			buildOpts: []AcceptSignatureBuildOption{WithParameter("nonce", Token("wrong-type"))},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"empty nonce in Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("nonce", ""),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"invalid structured field string for nonce": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("nonce", "bad\nvalue"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"duplicate nonce in Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("nonce", "first"),
				WithParameter("nonce", "second"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"additional extension at Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("other", "value"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires;other="value"`, hdr.Get(headerAcceptSignature))
			},
		},
		"static and dynamic extensions": {
			opts: []AcceptSignatureOption{
				WithParameter("audience", "service-a"),
				WithParameter("flag", true),
			},
			buildOpts: []AcceptSignatureBuildOption{WithParameter("challenge", Token("example"))},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires;audience="service-a";flag;challenge=example`, hdr.Get(headerAcceptSignature))
			},
		},
		"extension types": {
			opts: []AcceptSignatureOption{
				WithParameter("integer", 42),
				WithParameter("decimal", 1.5),
				WithParameter("bytes", []byte("hello")),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created;expires;integer=42;decimal=1.5;bytes=:aGVsbG8=:`, hdr.Get(headerAcceptSignature))
			},
		},
		"conflicting static and dynamic extension": {
			opts: []AcceptSignatureOption{
				WithParameter("audience", "static"),
			},
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("audience", "dynamic"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"duplicate extension at Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("audience", "first"),
				WithParameter("audience", "second"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"invalid extension at Build": {
			buildOpts: []AcceptSignatureBuildOption{
				WithParameter("other", "bad\nvalue"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, hdr)
			},
		},
		"failing getting the nonce": {
			opts: []AcceptSignatureOption{
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) {
					return "", errors.New("test error")
				})),
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, err.Error(), "test error")
			},
		},
		"Accept-Signature only is added": {
			opts: []AcceptSignatureOption{
				WithSignatureAlgorithm(EcdsaP256Sha256),
				WithKeyID("test"),
				WithComponents("@status", "x-foo-bar;req", "@method"),
				WithLabel("foo"),
				WithTag("bar"),
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "x-foo-bar";req "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				assert.Empty(t, hdr.Values(headerWantContentDigest))
			},
		},
		"Want-Content-Digest is omitted after overriding covered components": {
			opts: []AcceptSignatureOption{
				WithComponents("@status", "content-digest"),
				WithComponents("@method"),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, `sig=("@method");created;expires`, hdr.Get(headerAcceptSignature))
				assert.Empty(t, hdr.Values(headerWantContentDigest))
			},
		},
		"Accept-Signature and Want-Content-Digest headers are added with default algorithms": {
			opts: []AcceptSignatureOption{
				WithSignatureAlgorithm(EcdsaP256Sha256),
				WithKeyID("test"),
				WithComponents("@status", "content-digest", "@method"),
				WithLabel("foo"),
				WithTag("bar"),
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "content-digest" "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				values = hdr.Values(headerWantContentDigest)
				require.Len(t, values, 2)
				assert.ElementsMatch(t, values, []string{"sha-256=5", "sha-512=10"})
			},
		},
		"Accept-Signature and Want-Content-Digest headers are added with supplied algorithms": {
			opts: []AcceptSignatureOption{
				WithSignatureAlgorithm(EcdsaP256Sha256),
				WithKeyID("test"),
				WithComponents("@status", "content-digest", "@method"),
				WithLabel("foo"),
				WithTag("bar"),
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 1}),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "content-digest" "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				values = hdr.Values(headerWantContentDigest)
				require.Len(t, values, 1)
				assert.ElementsMatch(t, values, []string{"sha-512=1"})
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			hdr := make(http.Header)

			builder, err := NewAcceptSignature(tc.opts...)
			require.NoError(t, err)

			err = builder.Build(context.TODO(), hdr, tc.buildOpts...)

			tc.assert(t, err, hdr)
		})
	}

	t.Run("per-call nonce is not retained", func(t *testing.T) {
		calls := 0
		builder, err := NewAcceptSignature(WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) {
			calls++

			return "generated", nil
		})))
		require.NoError(t, err)

		first := make(http.Header)
		err = builder.Build(context.TODO(), first, WithParameter("nonce", "explicit"))
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;nonce="explicit"`, first.Get(headerAcceptSignature))
		assert.Zero(t, calls)

		second := make(http.Header)
		err = builder.Build(context.TODO(), second)
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;nonce="generated"`, second.Get(headerAcceptSignature))
		assert.Equal(t, 1, calls)
	})

	t.Run("per-call extension is not retained", func(t *testing.T) {
		builder, err := NewAcceptSignature(WithParameter("audience", "service-a"))
		require.NoError(t, err)

		first := make(http.Header)
		err = builder.Build(context.TODO(), first, WithParameter("challenge", "first"))
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;audience="service-a";challenge="first"`, first.Get(headerAcceptSignature))

		second := make(http.Header)
		err = builder.Build(context.TODO(), second, WithParameter("challenge", "second"))
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;audience="service-a";challenge="second"`, second.Get(headerAcceptSignature))

		third := make(http.Header)
		err = builder.Build(context.TODO(), third)
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;audience="service-a"`, third.Get(headerAcceptSignature))
	})

	t.Run("static byte sequence is not affected by caller mutation", func(t *testing.T) {
		value := []byte("before")
		builder, err := NewAcceptSignature(WithParameter("bytes", value))
		require.NoError(t, err)

		value[0] = 'X'
		hdr := make(http.Header)
		err = builder.Build(context.TODO(), hdr)
		require.NoError(t, err)
		assert.Equal(t, `sig=();created;expires;bytes=:YmVmb3Jl:`, hdr.Get(headerAcceptSignature))
	})
}

func TestNewSignatureRequest(t *testing.T) {
	t.Parallel()

	contentDigest := httpsfv.NewItem("content-digest")
	contentDigest.Params.Add("req", true)

	queryParam := httpsfv.NewItem("@query-param")
	queryParam.Params.Add("name", "a%3Bb")

	params := httpsfv.NewParams()
	params.Add(string(Created), true)
	params.Add(string(Expires), true)
	params.Add(string(KeyID), "test-key")
	params.Add(string(Alg), "ed25519")
	params.Add(string(Nonce), "abc")
	params.Add(string(Tag), "app-123")
	params.Add("audience", httpsfv.Token("service-a"))

	for uc, tc := range map[string]struct {
		list     httpsfv.InnerList
		expected SignatureRequest
		err      error
	}{
		"empty request": {
			list:     httpsfv.InnerList{Params: httpsfv.NewParams()},
			expected: SignatureRequest{Label: "sig", Components: []string{}},
		},
		"serializing component identifiers and copying parameters": {
			list: httpsfv.InnerList{
				Items:  []httpsfv.Item{httpsfv.NewItem("@method"), contentDigest, queryParam},
				Params: params,
			},
			expected: SignatureRequest{
				Label:      "sig",
				Components: []string{`"@method"`, `"content-digest";req`, `"@query-param";name="a%3Bb"`},
				KeyID:      "test-key",
				Algorithm:  Ed25519,
				Tag:        "app-123",
				Nonce:      "abc",
				Created:    true,
				Expires:    true,
				Extensions: SignatureParameters{"audience": Token("service-a")},
			},
		},
		"invalid component identifier": {
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{httpsfv.NewItem("@unsupported")},
			},
			err: ErrUnsupportedComponentIdentifier,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			request, err := newSignatureRequest("sig", tc.list)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, SignatureRequest{}, request)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, request)
		})
	}
}

func TestParseAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		values      []string
		expected    []SignatureRequest
		err         []error
		errContains []string
	}{
		"no header": {
			expected: []SignatureRequest{},
		},
		"single request": {
			values:   []string{`sig=("@method");tag="app-123"`},
			expected: []SignatureRequest{{Label: "sig", Components: []string{`"@method"`}, Tag: "app-123"}},
		},
		"multiple members keep their order": {
			values: []string{`zeta=("@status"), alpha=("@method");tag="a"`},
			expected: []SignatureRequest{
				{Label: "zeta", Components: []string{`"@status"`}},
				{Label: "alpha", Components: []string{`"@method"`}, Tag: "a"},
			},
		},
		"multiple field lines": {
			values: []string{`a=("@status")`, `b=("@method")`},
			expected: []SignatureRequest{
				{Label: "a", Components: []string{`"@status"`}},
				{Label: "b", Components: []string{`"@method"`}},
			},
		},
		"invalid structured fields": {
			values: []string{`good=("@status"), (`},
			err:    []error{ErrMalformedData},
		},
		"member is not an inner list": {
			values:   []string{`sig="@status"`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData},
		},
		"unusable member keeps the usable ones": {
			values: []string{`first=("@status"), bad=("@foo"), last=("@method")`},
			expected: []SignatureRequest{
				{Label: "first", Components: []string{`"@status"`}},
				{Label: "last", Components: []string{`"@method"`}},
			},
			err: []error{ErrMalformedData, ErrUnsupportedComponentIdentifier},
		},
		"every unusable member is reported": {
			values:   []string{`good=("@status"), scalar=1, comp=("@foo"), param=();created=1`},
			expected: []SignatureRequest{{Label: "good", Components: []string{`"@status"`}}},
			err: []error{
				ErrMalformedData,
				ErrUnsupportedComponentIdentifier,
				ErrMalformedSignatureParameter,
			},
			errContains: []string{`"scalar"`, `"comp"`, `"param"`},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			header := http.Header{}
			for _, value := range tc.values {
				header.Add(headerAcceptSignature, value)
			}

			requests, err := ParseAcceptSignature(header)
			assert.Equal(t, tc.expected, requests)

			if len(tc.err) == 0 {
				require.NoError(t, err)

				return
			}

			for _, expected := range tc.err {
				require.ErrorIs(t, err, expected)
			}

			for _, expected := range tc.errContains {
				require.ErrorContains(t, err, expected)
			}
		})
	}
}
