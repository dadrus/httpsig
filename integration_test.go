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
