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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignatureMiddleware(t *testing.T) {
	t.Parallel()

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sig, err := NewSigner(
		Key{Key: pkp256, KeyID: "test", Algorithm: EcdsaP256Sha256},
		WithComponents("@authority", "@method"),
		WithTTL(5*time.Second),
		WithTag("test"),
	)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		opts   []HandlerOption
		ver    Verifier
		assert func(t *testing.T, resp *http.Response, innerCalled bool)
	}{
		{
			uc: "without error",
			ver: func() Verifier {
				ver, err := NewVerifier(Key{Key: &pkp256.PublicKey, KeyID: "test", Algorithm: EcdsaP256Sha256},
					WithRequiredComponents("@authority", "@method"),
					WithValidityTolerance(1*time.Second),
					WithRequiredTag("test"),
				)
				require.NoError(t, err)

				return ver
			}(),
			assert: func(t *testing.T, resp *http.Response, innerCalled bool) {
				t.Helper()

				require.True(t, innerCalled)
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			},
		},
		{
			uc: "with error, default error handler",
			ver: func() Verifier {
				ver, err := NewVerifier(Key{Key: &pkp256.PublicKey, KeyID: "test", Algorithm: EcdsaP256Sha256},
					WithRequiredComponents("@authority", "@path"),
					WithRequiredTag("test"),
				)
				require.NoError(t, err)

				return ver
			}(),
			assert: func(t *testing.T, resp *http.Response, innerCalled bool) {
				t.Helper()

				require.False(t, innerCalled)
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			var handlerCalled bool

			middleware := NewVerifierMiddleware(tc.ver, tc.opts...)

			srv := httptest.NewServer(middleware(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				handlerCalled = true
			})))

			defer srv.Close()

			req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			client := http.Client{Transport: NewTransport(http.DefaultTransport, sig)}
			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			tc.assert(t, resp, handlerCalled)
		})
	}
}
