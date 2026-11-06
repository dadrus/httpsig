package httpsig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMessageVerifierAdaptorVerify(t *testing.T) {
	t.Parallel()

	message := []byte("signature base")
	verificationErr := errors.New("verification failed")

	for uc, tc := range map[string]struct {
		signature []byte
		verifyErr error
		assert    func(t *testing.T, err error)
	}{
		"verifies signature": {
			signature: []byte("signature"),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		"propagates verification error": {
			signature: []byte("signature"),
			verifyErr: verificationErr,
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, verificationErr)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			mockVerifier := NewMessageVerifierMock(t)
			mockVerifier.EXPECT().VerifyMessage(t.Context(), message, tc.signature).
				Return(tc.verifyErr).Once()

			verifier := &messageVerifierAdaptor{verifier: mockVerifier}
			tc.assert(t, verifier.verify(t.Context(), message, tc.signature))
		})
	}
}
