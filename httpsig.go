package httpsig

import (
	"context"
	"crypto"
	"errors"
	"net/http"
)

var (
	ErrUnsupportedKeyType             = errors.New("unsupported key type/format")
	ErrUnsupportedAlgorithm           = errors.New("unknown/unsupported algorithm")
	ErrInvalidKeySize                 = errors.New("invalid key size")
	ErrNoKeyProvided                  = errors.New("no key provided")
	ErrInvalidSignature               = errors.New("invalid signature")
	ErrVerificationFailed             = errors.New("verification failed")
	ErrMalformedData                  = errors.New("malformed data")
	ErrUnsupportedComponentIdentifier = errors.New("unsupported component identifier")
	ErrInvalidComponentIdentifier     = errors.New("invalid component identifier")
	ErrCanonicalization               = errors.New("failed to canonicalize component")
	ErrMalformedSignatureParameter    = errors.New("malformed signature parameter")
	ErrNoApplicableDigestFound        = errors.New("no applicable digest found")
	ErrVerifierCreation               = errors.New("verifier creation failed")
	ErrParameter                      = errors.New("parameter error")
	ErrValidity                       = errors.New("validity error")
)

type NoApplicableSignatureError struct {
	requiredSignatureParameters string
	wantContentDigest           bool
}

func (e *NoApplicableSignatureError) Error() string { return "no applicable signature found" }

func (e *NoApplicableSignatureError) Is(err error) bool {
	_, ok := err.(*NoApplicableSignatureError)

	return ok
}

func (e *NoApplicableSignatureError) Negotiate(header http.Header) {
	if len(e.requiredSignatureParameters) != 0 {
		header.Add(headerAcceptSignature, e.requiredSignatureParameters)
	}

	if e.wantContentDigest {
		header.Add(headerWantContentDigest, "sha-512=2")
		header.Add(headerWantContentDigest, "sha-256=1")
	}
}

const (
	headerAcceptSignature   = "Accept-Signature"
	headerSignature         = "Signature"
	headerSignatureInput    = "Signature-Input"
	headerContentDigest     = "Content-Digest"
	headerWantContentDigest = "Want-Content-Digest"
)

// SignatureAlgorithm is the signature algorithm to use.
// Available algorithms are:
// - RSASSA-PKCS1-v1_5 using SHA-256 (rsa-v1_5-sha256).
// - RSASSA-PSS using SHA-512 (rsa-pss-sha512).
// - ECDSA using curve P-256 DSS and SHA-256 (ecdsa-p256-sha256).
// - ECDSA using curve P-384 DSS and SHA-384 (ecdsa-p384-sha384).
// - EdDSA using curve edwards25519 (ed25519).
// - HMAC using SHA-256 (hmac-sha256).
type SignatureAlgorithm string

const (
	RsaPkcs1v15Sha256 SignatureAlgorithm = "rsa-v1_5-sha256"
	RsaPkcs1v15Sha384 SignatureAlgorithm = "rsa-v1_5-sha384"
	RsaPkcs1v15Sha512 SignatureAlgorithm = "rsa-v1_5-sha512"
	RsaPssSha256      SignatureAlgorithm = "rsa-pss-sha256"
	RsaPssSha384      SignatureAlgorithm = "rsa-pss-sha384"
	RsaPssSha512      SignatureAlgorithm = "rsa-pss-sha512"
	EcdsaP256Sha256   SignatureAlgorithm = "ecdsa-p256-sha256"
	EcdsaP384Sha384   SignatureAlgorithm = "ecdsa-p384-sha384"
	EcdsaP521Sha512   SignatureAlgorithm = "ecdsa-p521-sha512"
	Ed25519           SignatureAlgorithm = "ed25519"
	HmacSha256        SignatureAlgorithm = "hmac-sha256"
	HmacSha384        SignatureAlgorithm = "hmac-sha384"
	HmacSha512        SignatureAlgorithm = "hmac-sha512"
)

// DigestAlgorithm is the digest algorithm to use. Available algorithms are:
// - SHA-256 (sha-256).
// - SHA-512 (sha-512).
type DigestAlgorithm string

const (
	Sha256 DigestAlgorithm = "sha-256"
	Sha512 DigestAlgorithm = "sha-512"
)

type SignatureParameter string

const (
	KeyID   SignatureParameter = "keyid"
	Alg     SignatureParameter = "alg"
	Created SignatureParameter = "created"
	Expires SignatureParameter = "expires"
	Nonce   SignatureParameter = "nonce"
	Tag     SignatureParameter = "tag"
)

// Key is the key to use for signing or verifying.
type Key struct {
	// KeyID is the identifier of the key.
	KeyID string
	// Algorithm is the cryptographic algorithm to use with the key.
	Algorithm SignatureAlgorithm
	// Key is the actual key material, like public, private or a secret key.
	Key any
}

func (k Key) ResolveKey(_ context.Context, _ string) (Key, error) { return k, nil }

// nolint: gochecknoglobals
var supportedAlgs = map[string]crypto.Hash{
	"sha-256": crypto.SHA256,
	"sha-512": crypto.SHA512,
}
