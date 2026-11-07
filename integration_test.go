package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerifyParsedSignatureRequest(t *testing.T) {
	t.Parallel()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	requests, err := ParseAcceptSignature(http.Header{headerAcceptSignature: {
		`sig1=("@method" "@authority");keyid="key1";nonce="abc";tag="app";created;audience="service-a";nickname=%"Gr%c3%bc%c3%9fe";reviewed=@1794000000`,
	}})
	require.NoError(t, err)
	require.Len(t, requests, 1)

	request := requests[0]
	require.Equal(t, DisplayString("Grüße"), request.Extensions["nickname"])
	require.Equal(t, time.Unix(1794000000, 0), request.Extensions["reviewed"])

	signer, err := NewSigner(
		Key{Material: privKey, Algorithm: EcdsaP256Sha256},
		WithLabel(request.Label),
		WithKeyID(request.KeyID),
		WithComponents(request.Components...),
		WithTag(request.Tag),
		WithParameter("audience", request.Extensions["audience"]),
		WithParameter("nickname", request.Extensions["nickname"]),
		WithParameter("reviewed", request.Extensions["reviewed"]),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com/", nil)
	require.NoError(t, err)

	header, err := signer.Sign(MessageFromRequest(req), WithParameter(Nonce, request.Nonce))
	require.NoError(t, err)

	req.Header = header

	verifier, err := NewVerifier(
		Key{Material: privKey.Public(), Algorithm: EcdsaP256Sha256},
		WithRequiredTag(request.Tag,
			WithComponents(request.Components...),
			WithParameter("audience", "service-a"),
			WithParameter("nickname", DisplayString("Grüße")),
			WithParameter("reviewed", time.Unix(1794000000, 750000000).In(time.FixedZone("UTC+2", 2*60*60))),
		),
	)
	require.NoError(t, err)

	verified, err := verifier.Verify(MessageFromRequest(req))
	require.NoError(t, err)
	require.Len(t, verified, 1)

	nonce, ok := verified[0].Parameters.Nonce()
	require.True(t, ok)
	assert.Equal(t, request.Nonce, nonce)
	assert.Equal(t, request.Label, verified[0].Label)
	assert.Equal(t, DisplayString("Grüße"), verified[0].Parameters["nickname"])
	assert.Equal(t, time.Unix(1794000000, 0), verified[0].Parameters["reviewed"])
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
		WithParameter("nickname", DisplayString("Grüße")),
		WithParameter("reviewed", time.Unix(1794000000, 0)),
		WithExpiresTimestamp(false),
	)
	require.NoError(t, err)

	header := http.Header{}
	require.NoError(t, builder.Build(context.Background(), header, WithParameter(Nonce, "abc")))
	assert.Contains(t, header.Get(headerAcceptSignature), `;nickname=%"Gr%c3%bc%c3%9fe"`)
	assert.Contains(t, header.Get(headerAcceptSignature), `;reviewed=@1794000000`)

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
		Extensions: SignatureParameters{
			"audience": "service-a",
			"nickname": DisplayString("Grüße"),
			"reviewed": time.Unix(1794000000, 0),
		},
	}}, requests)
}

func TestParsedComponentsRoundTripThroughWithComponents(t *testing.T) {
	t.Parallel()

	const field = `sig=("@status" "content-digest";req "@query-param";name="a%3Bb" "@query-param";name="b%22c" "@query-param";name="d%5Ce" "x_test");created`

	requests, err := ParseAcceptSignature(http.Header{headerAcceptSignature: {field}})
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, []string{
		`"@status"`, `"content-digest";req`, `"@query-param";name="a%3Bb"`,
		`"@query-param";name="b%22c"`, `"@query-param";name="d%5Ce"`, `"x_test"`,
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
