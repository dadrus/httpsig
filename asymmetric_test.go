package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewECDSASigner(t *testing.T) {
	t.Parallel()

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkp521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *ecdsa.PrivateKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: RsaPkcs1v15Sha512, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: EcdsaP256Sha256, err: ErrNoKeyProvided},
		{uc: "invalid key size", alg: EcdsaP256Sha256, key: pkp521, err: ErrInvalidKeySize},
		{uc: string(EcdsaP256Sha256), alg: EcdsaP256Sha256, key: pkp256},
		{uc: string(EcdsaP384Sha384), alg: EcdsaP384Sha384, key: pkp384},
		{uc: string(EcdsaP521Sha512), alg: EcdsaP521Sha512, key: pkp521},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newECDSASigner(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.privateKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestECDSASignerSignPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkp521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		key *ecdsa.PrivateKey
		alg SignatureAlgorithm
	}{
		{alg: EcdsaP256Sha256, key: pkp256},
		{alg: EcdsaP384Sha384, key: pkp384},
		{alg: EcdsaP521Sha512, key: pkp521},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			sig, err := newECDSASigner(tc.key, "test", tc.alg)
			require.NoError(t, err)

			res, err := sig.signPayload(message)
			require.NoError(t, err)
			require.NotEmpty(t, res)

			hasher := sig.hash.New()
			_, _ = hasher.Write(message)
			hashed := hasher.Sum(nil)

			curveBits := sig.privateKey.Curve.Params().BitSize

			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes++
			}

			r := big.NewInt(0).SetBytes(res[:keyBytes])
			s := big.NewInt(0).SetBytes(res[keyBytes:])

			match := ecdsa.Verify(&sig.privateKey.PublicKey, hashed, r, s)
			require.True(t, match)
		})
	}
}

func TestNewRSASigner(t *testing.T) {
	t.Parallel()

	pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	pk4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *rsa.PrivateKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: EcdsaP256Sha256, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: RsaPkcs1v15Sha512, err: ErrNoKeyProvided},
		{uc: string(RsaPkcs1v15Sha256), alg: RsaPkcs1v15Sha256, key: pk2048},
		{uc: string(RsaPkcs1v15Sha384), alg: RsaPkcs1v15Sha384, key: pk3072},
		{uc: string(RsaPkcs1v15Sha512), alg: RsaPkcs1v15Sha512, key: pk4096},
		{uc: string(RsaPssSha256), alg: RsaPssSha256, key: pk2048},
		{uc: string(RsaPssSha384), alg: RsaPssSha384, key: pk3072},
		{uc: string(RsaPssSha512), alg: RsaPssSha512, key: pk4096},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newRSASigner(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.privateKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestRSASignerSignPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pk512, err := rsa.GenerateKey(rand.Reader, 512) //nolint:gosec
	require.NoError(t, err)

	pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	pk4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *rsa.PrivateKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "message too long", key: pk512, alg: RsaPkcs1v15Sha512, err: rsa.ErrMessageTooLong},
		{uc: "2048 key with RsaPkcs1v15Sha256", key: pk2048, alg: RsaPkcs1v15Sha256},
		{uc: "3072 key with RsaPkcs1v15Sha384", key: pk3072, alg: RsaPkcs1v15Sha384},
		{uc: "4096 key with RsaPkcs1v15Sha512", key: pk4096, alg: RsaPkcs1v15Sha512},
		{uc: "2048 key with RsaPssSha256", key: pk2048, alg: RsaPssSha256},
		{uc: "3072 key with RsaPssSha384", key: pk3072, alg: RsaPssSha384},
		{uc: "4096 key with RsaPssSha512", key: pk4096, alg: RsaPssSha512},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newRSASigner(tc.key, "test", tc.alg)
			require.NoError(t, err)

			res, err := sig.signPayload(message)
			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, res)

				hasher := sig.hash.New()
				_, _ = hasher.Write(message)
				hashed := hasher.Sum(nil)

				switch sig.alg {
				case RsaPkcs1v15Sha256, RsaPkcs1v15Sha384, RsaPkcs1v15Sha512:
					err = rsa.VerifyPKCS1v15(&sig.privateKey.PublicKey, sig.hash, hashed, res)
				case RsaPssSha256, RsaPssSha384, RsaPssSha512:
					err = rsa.VerifyPSS(&sig.privateKey.PublicKey, sig.hash, hashed, res, &rsa.PSSOptions{
						SaltLength: rsa.PSSSaltLengthEqualsHash,
					})
				}

				require.NoError(t, err)
			}
		})
	}
}

func TestNewEd25519Signer(t *testing.T) {
	t.Parallel()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key ed25519.PrivateKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: RsaPssSha512, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: Ed25519, err: ErrNoKeyProvided},
		{uc: "invalid key size", alg: Ed25519, key: ed25519.PrivateKey{0x00}, err: ErrInvalidKeySize},
		{uc: "success", alg: Ed25519, key: privKey},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newEd25519Signer(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.privateKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestEd25519SignerSignPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sig, err := newEd25519Signer(privKey, "test", Ed25519)
	require.NoError(t, err)

	res, err := sig.signPayload(message)
	require.NoError(t, err)

	ok := ed25519.Verify(pubKey, message, res)
	require.True(t, ok)
}

func TestNewECDSAVerifier(t *testing.T) {
	t.Parallel()

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkp521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *ecdsa.PublicKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: RsaPkcs1v15Sha512, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: EcdsaP256Sha256, err: ErrNoKeyProvided},
		{uc: "invalid key size", alg: EcdsaP256Sha256, key: &pkp521.PublicKey, err: ErrInvalidKeySize},
		{uc: string(EcdsaP256Sha256), alg: EcdsaP256Sha256, key: &pkp256.PublicKey},
		{uc: string(EcdsaP384Sha384), alg: EcdsaP384Sha384, key: &pkp384.PublicKey},
		{uc: string(EcdsaP521Sha512), alg: EcdsaP521Sha512, key: &pkp521.PublicKey},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newECDSAVerifier(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.publicKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestECDSAverifierVerifyPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pkp521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		key *ecdsa.PrivateKey
		alg SignatureAlgorithm
	}{
		{alg: EcdsaP256Sha256, key: pkp256},
		{alg: EcdsaP384Sha384, key: pkp384},
		{alg: EcdsaP521Sha512, key: pkp521},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			sig, err := newECDSASigner(tc.key, "test", tc.alg)
			require.NoError(t, err)

			res, err := sig.signPayload(message)
			require.NoError(t, err)
			require.NotEmpty(t, res)

			ver, err := newECDSAVerifier(&tc.key.PublicKey, "test", tc.alg)
			require.NoError(t, err)

			err = ver.verifyPayload(message, res)
			require.NoError(t, err)

			err = ver.verifyPayload([]byte("test"), res)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

func TestNewRSAVerifier(t *testing.T) {
	t.Parallel()

	pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	pk4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *rsa.PublicKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: EcdsaP256Sha256, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: RsaPkcs1v15Sha512, err: ErrNoKeyProvided},
		{uc: string(RsaPkcs1v15Sha256), alg: RsaPkcs1v15Sha256, key: &pk2048.PublicKey},
		{uc: string(RsaPkcs1v15Sha384), alg: RsaPkcs1v15Sha384, key: &pk3072.PublicKey},
		{uc: string(RsaPkcs1v15Sha512), alg: RsaPkcs1v15Sha512, key: &pk4096.PublicKey},
		{uc: string(RsaPssSha256), alg: RsaPssSha256, key: &pk2048.PublicKey},
		{uc: string(RsaPssSha384), alg: RsaPssSha384, key: &pk3072.PublicKey},
		{uc: string(RsaPssSha512), alg: RsaPssSha512, key: &pk4096.PublicKey},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newRSAVerifier(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.publicKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestRSAVerifierVerifyPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pk3072, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	pk4096, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key *rsa.PrivateKey
		alg SignatureAlgorithm
	}{
		{uc: "2048 key with RsaPkcs1v15Sha256", key: pk2048, alg: RsaPkcs1v15Sha256},
		{uc: "3072 key with RsaPkcs1v15Sha384", key: pk3072, alg: RsaPkcs1v15Sha384},
		{uc: "4096 key with RsaPkcs1v15Sha512", key: pk4096, alg: RsaPkcs1v15Sha512},
		{uc: "2048 key with RsaPssSha256", key: pk2048, alg: RsaPssSha256},
		{uc: "3072 key with RsaPssSha384", key: pk3072, alg: RsaPssSha384},
		{uc: "4096 key with RsaPssSha512", key: pk4096, alg: RsaPssSha512},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newRSASigner(tc.key, "test", tc.alg)
			require.NoError(t, err)

			res, err := sig.signPayload(message)
			require.NoError(t, err)
			require.NotEmpty(t, res)

			ver, err := newRSAVerifier(&tc.key.PublicKey, "test", tc.alg)
			require.NoError(t, err)

			err = ver.verifyPayload(message, res)
			require.NoError(t, err)

			err = ver.verifyPayload([]byte("test"), res)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidSignature)
		})
	}
}

func TestNewEd25519Verifier(t *testing.T) {
	t.Parallel()

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc  string
		key ed25519.PublicKey
		alg SignatureAlgorithm
		err error
	}{
		{uc: "unsupported algorithm", alg: RsaPssSha512, err: ErrUnsupportedAlgorithm},
		{uc: "no key provided", alg: Ed25519, err: ErrNoKeyProvided},
		{uc: "invalid key size", alg: Ed25519, key: ed25519.PublicKey{0x00}, err: ErrInvalidKeySize},
		{uc: "success", alg: Ed25519, key: pubKey},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newEd25519Verifier(tc.key, "test", tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				assert.Equal(t, "test", sig.keyID())
				assert.Equal(t, tc.key, sig.publicKey)
				assert.Equal(t, tc.alg, sig.algorithm())
			}
		})
	}
}

func TestEd25519VerifierVerifyPayload(t *testing.T) {
	t.Parallel()

	message := []byte("test message")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sig, err := newEd25519Signer(privKey, "test", Ed25519)
	require.NoError(t, err)

	res, err := sig.signPayload(message)
	require.NoError(t, err)

	ver, err := newEd25519Verifier(pubKey, "test", sig.alg)
	require.NoError(t, err)

	err = ver.verifyPayload(message, res)
	require.NoError(t, err)

	err = ver.verifyPayload([]byte("test"), res)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidSignature)
}
