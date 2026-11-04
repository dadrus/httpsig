package httpsig

import (
	"crypto/hmac"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSymmetricSigner(t *testing.T) {
	t.Parallel()

	k256 := make([]byte, 32)
	k384 := make([]byte, 48)
	k512 := make([]byte, 64)

	n, err := rand.Read(k256)
	require.NoError(t, err)
	require.Equal(t, len(k256), n)

	n, err = rand.Read(k384)
	require.NoError(t, err)
	require.Equal(t, len(k384), n)

	n, err = rand.Read(k512)
	require.NoError(t, err)
	require.Equal(t, len(k512), n)

	for _, tc := range []struct {
		uc  string
		key []byte
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: RsaPkcs1v15Sha512, err: ErrUnsupportedAlgorithm},
		{uc: string(HmacSha256), alg: HmacSha256, key: k256},
		{uc: string(HmacSha384), alg: HmacSha384, key: k384},
		{uc: string(HmacSha512), alg: HmacSha512, key: k512},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newSymmetricSigner(tc.key, tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, tc.key, sig.key)
			}
		})
	}
}

func TestSymmetricSignerSignPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	k256 := make([]byte, 32)
	k384 := make([]byte, 48)
	k512 := make([]byte, 64)

	n, err := rand.Read(k256)
	require.NoError(t, err)
	require.Equal(t, len(k256), n)

	n, err = rand.Read(k384)
	require.NoError(t, err)
	require.Equal(t, len(k384), n)

	n, err = rand.Read(k512)
	require.NoError(t, err)
	require.Equal(t, len(k512), n)

	for _, tc := range []struct {
		key []byte
		alg SignatureAlgorithm
	}{
		{alg: HmacSha256, key: k256},
		{alg: HmacSha384, key: k384},
		{alg: HmacSha512, key: k512},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			sig, err := newSymmetricSigner(tc.key, tc.alg)
			require.NoError(t, err)

			res, err := sig.sign(t.Context(), message)
			require.NoError(t, err)
			require.NotEmpty(t, res)

			hmacer := hmac.New(sig.hash.New, sig.key)
			_, _ = hmacer.Write(message)
			mac := hmacer.Sum(nil)

			assert.Equal(t, mac, res)
		})
	}
}

func TestSymmetricSignerVerifyPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	key := make([]byte, 32)

	n, err := rand.Read(key)
	require.NoError(t, err)
	require.Equal(t, len(key), n)

	sig, err := newSymmetricSigner(key, HmacSha256)
	require.NoError(t, err)

	res, err := sig.sign(t.Context(), message)
	require.NoError(t, err)

	err = sig.verify(t.Context(), message, res)
	require.NoError(t, err)

	err = sig.verify(t.Context(), []byte("test"), res)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidSignature)
}
