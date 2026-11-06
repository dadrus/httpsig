package httpsig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageSignerAdaptorSign(t *testing.T) {
	t.Parallel()

	message := []byte("signature base")
	signingErr := errors.New("signing failed")

	for uc, tc := range map[string]struct {
		signature []byte
		signErr   error
		assert    func(t *testing.T, signature []byte, err error)
	}{
		"returns signature unchanged": {
			signature: []byte("signature"),
			assert: func(t *testing.T, signature []byte, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, []byte("signature"), signature)
			},
		},
		"propagates signing error": {
			signErr: signingErr,
			assert: func(t *testing.T, signature []byte, err error) {
				t.Helper()
				require.ErrorIs(t, err, signingErr)
				assert.Nil(t, signature)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			mockSigner := NewMessageSignerMock(t)
			mockSigner.EXPECT().SignMessage(t.Context(), message).
				Return(tc.signature, tc.signErr).Once()

			signer := &messageSignerAdaptor{signer: mockSigner}
			signature, err := signer.sign(t.Context(), message)
			tc.assert(t, signature, err)
		})
	}
}
