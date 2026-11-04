package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransport(t *testing.T) {
	t.Parallel()

	var receivedHeader http.Header

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedHeader = req.Header.Clone()

		rw.WriteHeader(http.StatusOK)
	}))

	defer srv.Close()

	sig, err := NewSigner(
		Key{Key: pkp256, KeyID: "test", Algorithm: EcdsaP256Sha256},
		WithComponents("@authority", "@method"),
		WithTTL(5*time.Second),
		WithTag("test"),
	)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	client := http.Client{Transport: NewTransport(http.DefaultTransport, sig)}
	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	inputDict, err := httpsfv.UnmarshalDictionary(receivedHeader.Values(headerSignatureInput))
	require.NoError(t, err)

	require.Contains(t, inputDict.Names(), "sig")
	member, present := inputDict.Get("sig")
	require.True(t, present)

	require.IsType(t, httpsfv.InnerList{}, member)
	list := member.(httpsfv.InnerList)
	require.Len(t, list.Items, 2)
	assert.Equal(t, "@authority", list.Items[0].Value)
	assert.Equal(t, "@method", list.Items[1].Value)
	assert.ElementsMatch(t, list.Params.Names(), []string{"created", "expires", "keyid", "alg", "nonce", "tag"})

	sigDict, err := httpsfv.UnmarshalDictionary(receivedHeader.Values(headerSignature))
	require.NoError(t, err)

	require.Contains(t, sigDict.Names(), "sig")
	member, present = sigDict.Get("sig")
	require.True(t, present)
	require.IsType(t, httpsfv.Item{}, member)
	item := member.(httpsfv.Item)
	require.IsType(t, []byte{}, item.Value)
}
