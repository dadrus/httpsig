package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"slices"
)

func newECDSASigner(privateKey *ecdsa.PrivateKey, kid string, alg SignatureAlgorithm) (*ecdsaSigner, error) {
	var (
		expectedBitSize int
		hash            crypto.Hash
	)

	switch alg {
	case EcdsaP256Sha256:
		expectedBitSize = 256
		hash = crypto.SHA256
	case EcdsaP384Sha384:
		expectedBitSize = 384
		hash = crypto.SHA384
	case EcdsaP521Sha512:
		expectedBitSize = 521
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if privateKey == nil {
		return nil, ErrNoKeyProvided
	}

	curveBits := privateKey.Curve.Params().BitSize
	if expectedBitSize != curveBits {
		return nil, fmt.Errorf("%w: expected %d bit key, got %d bits instead",
			ErrInvalidKeySize, expectedBitSize, curveBits)
	}

	return &ecdsaSigner{
		alg:        alg,
		privateKey: privateKey,
		kid:        kid,
		hash:       hash,
	}, nil
}

type ecdsaSigner struct {
	alg        SignatureAlgorithm
	privateKey *ecdsa.PrivateKey
	kid        string
	hash       crypto.Hash
}

func (ecs *ecdsaSigner) keyID() string { return ecs.kid }

func (ecs *ecdsaSigner) algorithm() SignatureAlgorithm { return ecs.alg }

func (ecs *ecdsaSigner) signPayload(payload []byte) ([]byte, error) {
	hasher := ecs.hash.New()
	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, ecs.privateKey, hashed) //nolint: varnamelen
	if err != nil {
		return nil, err
	}

	curveBits := ecs.privateKey.Curve.Params().BitSize

	keyBytes := curveBits / 8 //nolint:mnd
	if curveBits%8 > 0 {
		keyBytes++
	}

	// We serialize the outputs (r and s) into big-endian byte arrays and pad
	// them with zeros on the left to make sure the sizes work out. Both arrays
	// must be keyBytes long, and the output must be 2*keyBytes long.
	rBytes := r.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := s.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	return slices.Concat(rBytesPadded, sBytesPadded), nil
}

func newRSASigner(privateKey *rsa.PrivateKey, kid string, alg SignatureAlgorithm) (*rsaSigner, error) {
	var hash crypto.Hash

	switch alg {
	case RsaPkcs1v15Sha256, RsaPssSha256:
		hash = crypto.SHA256
	case RsaPkcs1v15Sha384, RsaPssSha384:
		hash = crypto.SHA384
	case RsaPkcs1v15Sha512, RsaPssSha512:
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if privateKey == nil {
		return nil, ErrNoKeyProvided
	}

	return &rsaSigner{
		alg:        alg,
		hash:       hash,
		privateKey: privateKey,
		kid:        kid,
	}, nil
}

type rsaSigner struct {
	alg        SignatureAlgorithm
	privateKey *rsa.PrivateKey
	kid        string
	hash       crypto.Hash
}

func (s *rsaSigner) keyID() string { return s.kid }

func (s *rsaSigner) algorithm() SignatureAlgorithm { return s.alg }

func (s *rsaSigner) signPayload(payload []byte) ([]byte, error) {
	var (
		out []byte
		err error
	)

	hasher := s.hash.New()
	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	switch s.alg { //nolint:exhaustive
	case RsaPkcs1v15Sha256, RsaPkcs1v15Sha384, RsaPkcs1v15Sha512:
		// random parameter is legacy and ignored, and it can be nil.
		// https://cs.opensource.google/go/go/+/refs/tags/go1.20:src/crypto/rsa/pkcs1v15.go;l=263;bpv=0;bpt=1
		out, err = rsa.SignPKCS1v15(rand.Reader, s.privateKey, s.hash, hashed)
	case RsaPssSha256, RsaPssSha384, RsaPssSha512:
		out, err = rsa.SignPSS(rand.Reader, s.privateKey, s.hash, hashed, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		})
	}

	if err != nil {
		return nil, err
	}

	return out, nil
}

func newEd25519Signer(privateKey ed25519.PrivateKey, kid string, alg SignatureAlgorithm) (*ed25519Signer, error) {
	if alg != Ed25519 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if privateKey == nil {
		return nil, ErrNoKeyProvided
	}

	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKeySize
	}

	return &ed25519Signer{
		alg:        alg,
		privateKey: privateKey,
		kid:        kid,
	}, nil
}

type ed25519Signer struct {
	alg        SignatureAlgorithm
	privateKey ed25519.PrivateKey
	kid        string
}

func (s *ed25519Signer) keyID() string { return s.kid }

func (s *ed25519Signer) algorithm() SignatureAlgorithm { return s.alg }

func (s *ed25519Signer) signPayload(payload []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, payload), nil
}

func newECDSAVerifier(publicKey *ecdsa.PublicKey, keyID string, alg SignatureAlgorithm) (*ecdsaVerifier, error) {
	var (
		expectedBitSize int
		hash            crypto.Hash
	)

	switch alg {
	case EcdsaP256Sha256:
		expectedBitSize = 256
		hash = crypto.SHA256
	case EcdsaP384Sha384:
		expectedBitSize = 384
		hash = crypto.SHA384
	case EcdsaP521Sha512:
		expectedBitSize = 521
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if publicKey == nil {
		return nil, ErrNoKeyProvided
	}

	curveBits := publicKey.Curve.Params().BitSize
	if expectedBitSize != curveBits {
		return nil, fmt.Errorf("%w: expected %d bit key, got %d bits instead",
			ErrInvalidKeySize, expectedBitSize, curveBits)
	}

	return &ecdsaVerifier{
		alg:       alg,
		publicKey: publicKey,
		kid:       keyID,
		hash:      hash,
	}, nil
}

type ecdsaVerifier struct {
	publicKey *ecdsa.PublicKey
	alg       SignatureAlgorithm
	kid       string
	hash      crypto.Hash
}

func (v *ecdsaVerifier) keyID() string { return v.kid }

func (v *ecdsaVerifier) algorithm() SignatureAlgorithm { return v.alg }

func (v *ecdsaVerifier) verifyPayload(payload []byte, signature []byte) error {
	hasher := v.hash.New()
	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	curveBits := v.publicKey.Curve.Params().BitSize

	keyBytes := curveBits / 8 //nolint:mnd
	if curveBits%8 > 0 {
		keyBytes++
	}

	r := big.NewInt(0).SetBytes(signature[:keyBytes])
	s := big.NewInt(0).SetBytes(signature[keyBytes:])

	if match := ecdsa.Verify(v.publicKey, hashed, r, s); !match {
		return ErrInvalidSignature
	}

	return nil
}

func newRSAVerifier(publicKey *rsa.PublicKey, kid string, alg SignatureAlgorithm) (*rsaVerifier, error) {
	var hash crypto.Hash

	switch alg {
	case RsaPkcs1v15Sha256, RsaPssSha256:
		hash = crypto.SHA256
	case RsaPkcs1v15Sha384, RsaPssSha384:
		hash = crypto.SHA384
	case RsaPkcs1v15Sha512, RsaPssSha512:
		hash = crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if publicKey == nil {
		return nil, ErrNoKeyProvided
	}

	return &rsaVerifier{
		alg:       alg,
		hash:      hash,
		publicKey: publicKey,
		kid:       kid,
	}, nil
}

type rsaVerifier struct {
	publicKey *rsa.PublicKey
	alg       SignatureAlgorithm
	kid       string
	hash      crypto.Hash
}

func (v *rsaVerifier) keyID() string { return v.kid }

func (v *rsaVerifier) algorithm() SignatureAlgorithm { return v.alg }

func (v *rsaVerifier) verifyPayload(payload []byte, signature []byte) error {
	hasher := v.hash.New()

	// According to documentation, Write() on hash never fails
	_, _ = hasher.Write(payload)
	hashed := hasher.Sum(nil)

	var err error

	switch v.alg { //nolint:exhaustive
	case RsaPkcs1v15Sha256, RsaPkcs1v15Sha384, RsaPkcs1v15Sha512:
		err = rsa.VerifyPKCS1v15(v.publicKey, v.hash, hashed, signature)
	case RsaPssSha256, RsaPssSha384, RsaPssSha512:
		err = rsa.VerifyPSS(v.publicKey, v.hash, hashed, signature, nil)
	}

	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return nil
}

func newEd25519Verifier(publicKey ed25519.PublicKey, keyID string, alg SignatureAlgorithm) (*ed25519Verifier, error) {
	if alg != Ed25519 {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}

	if publicKey == nil {
		return nil, ErrNoKeyProvided
	}

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeySize
	}

	return &ed25519Verifier{
		publicKey: publicKey,
		alg:       alg,
		kid:       keyID,
	}, nil
}

type ed25519Verifier struct {
	alg       SignatureAlgorithm
	publicKey ed25519.PublicKey
	kid       string
}

func (v *ed25519Verifier) keyID() string { return v.kid }

func (v *ed25519Verifier) algorithm() SignatureAlgorithm { return v.alg }

func (v *ed25519Verifier) verifyPayload(payload []byte, signature []byte) error {
	if ok := ed25519.Verify(v.publicKey, payload, signature); !ok {
		return ErrInvalidSignature
	}

	return nil
}
