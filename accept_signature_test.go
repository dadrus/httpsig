package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				Components: []string{"@method", "@target-uri", "content-digest"},
				KeyID:      "test-key",
				Algorithm:  Ed25519,
				Tag:        "app-123",
				Nonce:      "abc",
				Created:    true,
				Expires:    true,
			}},
		},
		"false boolean parameters": {
			values:   []string{`sig=();created=?0;expires=?0`},
			expected: []SignatureRequest{{Label: "sig", Components: []string{}}},
		},
		"component identifier parameters": {
			values: []string{`sig=("content-digest";req "@query-param";name="a;b" "x-dict";key="k";sf)`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{`content-digest;req`, `@query-param;name="a;b"`, `x-dict;key="k";sf`},
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
				{Label: "zeta", Components: []string{"@status"}},
				{Label: "alpha", Components: []string{"@method"}, Tag: "a"},
			},
		},
		"multiple field lines": {
			values: []string{`a=("@status")`, `b=("@method")`},
			expected: []SignatureRequest{
				{Label: "a", Components: []string{"@status"}},
				{Label: "b", Components: []string{"@method"}},
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
			expected:    []SignatureRequest{{Label: "good", Components: []string{"@method"}}},
			err:         []error{ErrMalformedData},
			errContains: []string{"duplicate component identifier"},
		},
		"same component with distinct parameters": {
			values: []string{`sig=("@query-param";name="foo" "@query-param";name="bar")`},
			expected: []SignatureRequest{{
				Label:      "sig",
				Components: []string{`@query-param;name="foo"`, `@query-param;name="bar"`},
			}},
		},
		"unusable member keeps the usable ones": {
			values: []string{`first=("@status"), bad=("@foo"), last=("@method")`},
			expected: []SignatureRequest{
				{Label: "first", Components: []string{"@status"}},
				{Label: "last", Components: []string{"@method"}},
			},
			err: []error{ErrMalformedData, ErrUnsupportedComponentIdentifier},
		},
		"every unusable member is reported": {
			values:   []string{`good=("@status"), scalar=1, comp=("@foo"), param=();created=1`},
			expected: []SignatureRequest{{Label: "good", Components: []string{"@status"}}},
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
		Components: []string{"@status", "content-digest;req", `@query-param;name="Pet"`},
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

	builder, err := NewAcceptSignature(
		WithComponents(requests[0].Components...),
		WithExpiresTimestamp(false),
	)
	require.NoError(t, err)

	header := http.Header{}
	require.NoError(t, builder.Build(context.Background(), header))

	assert.Equal(t, field, header.Get(headerAcceptSignature))
}

func TestSignAndVerifyParsedSignatureRequest(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	requests, err := ParseAcceptSignature(http.Header{headerAcceptSignature: {
		`sig1=("@method" "@authority");keyid="key1";nonce="abc";tag="app";created;audience="service-a"`,
	}})
	require.NoError(t, err)
	require.Len(t, requests, 1)

	request := requests[0]

	signer, err := NewSigner(
		Key{Material: privKey, Algorithm: EcdsaP256Sha256},
		WithLabel(request.Label),
		WithKeyID(request.KeyID),
		WithComponents(request.Components...),
		WithTag(request.Tag),
		WithParameter("audience", request.Extensions["audience"]),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)

	header, err := signer.Sign(MessageFromRequest(req), WithParameter(Nonce, request.Nonce))
	require.NoError(t, err)

	req.Header = header

	verifier, err := NewVerifier(
		Key{Material: privKey.Public(), Algorithm: EcdsaP256Sha256},
		WithRequiredTag(request.Tag, WithComponents(request.Components...), WithParameter("audience", "service-a")),
	)
	require.NoError(t, err)

	verified, err := verifier.Verify(MessageFromRequest(req))
	require.NoError(t, err)
	require.Len(t, verified, 1)

	nonce, ok := verified[0].Parameters.Nonce()
	require.True(t, ok)
	assert.Equal(t, request.Nonce, nonce)
	assert.Equal(t, request.Label, verified[0].Label)
}
