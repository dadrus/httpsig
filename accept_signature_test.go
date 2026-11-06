package httpsig

import (
	"context"
	"errors"
	"net/http"
	"testing"

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
		"empty components and no parameters": {
			values:   []string{`sig=()`},
			expected: []SignatureRequest{{Label: "sig", Components: []string{}}},
		},
		"all standard parameters": {
			values: []string{
				`sig1=("@method" "@target-uri" "content-digest");` +
					`created;expires;keyid="test-key";alg="ed25519";nonce="abc";tag="app-123"`,
			},
			expected: []SignatureRequest{{
				Label:      "sig1",
				Components: []string{`"@method"`, `"@target-uri"`, `"content-digest"`},
				KeyID:      "test-key",
				Algorithm:  Ed25519,
				Tag:        "app-123",
				Nonce:      "abc",
				Created:    true,
				Expires:    true,
			}},
		},
		"false created flag": {
			values:   []string{`sig=();created=?0`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrMalformedSignatureParameter},
		},
		"false expires flag": {
			values:   []string{`sig=();expires=?0`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrMalformedSignatureParameter},
		},
		"explicit true boolean parameters": {
			values: []string{`sig=();created=?1;expires=?1`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{},
				Created:    true,
				Expires:    true,
			}},
		},
		"component identifier parameters": {
			values: []string{`sig=("content-digest";req "@query-param";name="a;b" "x-dict";key="k";sf)`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{`"content-digest";req`, `"@query-param";name="a;b"`, `"x-dict";key="k";sf`},
			}},
		},
		"component names requiring quotes": {
			values: []string{`sig=("a;req" "b\"c" "d\\e")`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{`"a;req"`, `"b\"c"`, `"d\\e"`},
			}},
		},
		"extension parameters": {
			values: []string{`sig=();str="v";tok=bar;flag;num=42;dec=1.5;bin=:AQID:;disp=%"caf%c3%a9"`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{},
				Extensions: SignatureParameters{
					"str":  "v",
					"tok":  Token("bar"),
					"flag": true,
					"num":  int64(42),
					"dec":  1.5,
					"bin":  []byte{1, 2, 3},
					"disp": "café",
				},
			}},
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
		"not a dictionary": {
			values: []string{`("@status")`},
			err:    []error{ErrMalformedData},
		},
		"field is not valid structured fields": {
			values: []string{`good=("@status"), (`},
			err:    []error{ErrMalformedData},
		},
		"member is not an inner list": {
			values:   []string{`sig="@status"`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData},
		},
		"non-string component identifier": {
			values:   []string{`sig=(1)`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrInvalidComponentIdentifier},
		},
		"uppercase component name": {
			values:   []string{`sig=("Content-Type")`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrInvalidComponentIdentifier},
		},
		"query parameter without name": {
			values:   []string{`sig=("@query-param")`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrInvalidComponentIdentifier},
		},
		"query parameter with non-string name": {
			values:   []string{`sig=("@query-param";name=foo)`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrInvalidComponentIdentifier},
		},
		"duplicate component identifier": {
			values:      []string{`sig=("@method" "@method")`},
			expected:    []SignatureRequest{},
			err:         []error{ErrMalformedData},
			errContains: []string{"duplicate component identifier"},
		},
		"duplicate component identifier with reordered parameters": {
			values: []string{
				`bad=("x-dict";key="foo";sf "x-dict";sf;key="foo"), good=("@method")`,
			},
			expected:    []SignatureRequest{{Label: "good", Components: []string{`"@method"`}}},
			err:         []error{ErrMalformedData},
			errContains: []string{"duplicate component identifier"},
		},
		"same component with distinct parameters": {
			values: []string{`sig=("@query-param";name="foo" "@query-param";name="bar")`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{`"@query-param";name="foo"`, `"@query-param";name="bar"`},
			}},
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
		"created with a value": {
			values:   []string{`sig=();created=1618884473`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrMalformedSignatureParameter},
		},
		"expires with a value": {
			values:   []string{`sig=();expires=1618884473`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrMalformedSignatureParameter},
		},
		"keyid of wrong type": {
			values:   []string{`sig=();keyid=1`},
			expected: []SignatureRequest{},
			err:      []error{ErrMalformedData, ErrMalformedSignatureParameter},
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

func TestParseAcceptSignatureNilHeader(t *testing.T) {
	t.Parallel()

	requests, err := ParseAcceptSignature(nil)

	require.NoError(t, err)
	assert.Empty(t, requests)
}

func TestParseAcceptSignatureBuilderOutput(t *testing.T) {
	t.Parallel()

	builder, err := NewAcceptSignature(
		WithLabel("bar"),
		WithKeyID("foo"),
		WithSignatureAlgorithm(EcdsaP256Sha256),
		WithComponents("@status", "content-digest;req", `@query-param;name="Pet"`),
		WithTag("awesome-app"),
		WithParameter("audience", "service-a"),
		WithExpiresTimestamp(false),
	)
	require.NoError(t, err)

	header := http.Header{}
	require.NoError(t, builder.Build(context.Background(), header, WithParameter(Nonce, "abc")))

	requests, err := ParseAcceptSignature(header)

	require.NoError(t, err)
	assert.Equal(t, []SignatureRequest{{
		Label:      "bar",
		Components: []string{`"@status"`, `"content-digest";req`, `"@query-param";name="Pet"`},
		KeyID:      "foo",
		Algorithm:  EcdsaP256Sha256,
		Tag:        "awesome-app",
		Nonce:      "abc",
		Created:    true,
		Extensions: SignatureParameters{"audience": "service-a"},
	}}, requests)
}

func TestParsedComponentsRoundTripThroughWithComponents(t *testing.T) {
	t.Parallel()

	const field = `sig=("@status" "content-digest";req "@query-param";name="a;b" "a;req" "b\"c" "d\\e");created`

	requests, err := ParseAcceptSignature(http.Header{headerAcceptSignature: {field}})
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, []string{
		`"@status"`, `"content-digest";req`, `"@query-param";name="a;b"`,
		`"a;req"`, `"b\"c"`, `"d\\e"`,
	}, requests[0].Components)

	builder, err := NewAcceptSignature(
		WithComponents(requests[0].Components...),
		WithExpiresTimestamp(false),
	)
	require.NoError(t, err)

	header := http.Header{}
	require.NoError(t, builder.Build(context.Background(), header))

	assert.Equal(t, field, header.Get(headerAcceptSignature))
}
