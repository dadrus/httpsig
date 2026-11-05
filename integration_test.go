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
