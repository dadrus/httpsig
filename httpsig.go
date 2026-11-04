package httpsig

import (
	"context"
	"crypto"
	"errors"
	"net/http"
)

var (
	// ErrUnsupportedKeyType indicates that the supplied key material has an unsupported Go type.
	ErrUnsupportedKeyType = errors.New("unsupported key type/format")

	// ErrUnsupportedAlgorithm indicates that the requested signature or digest algorithm is unsupported.
	ErrUnsupportedAlgorithm = errors.New("unknown/unsupported algorithm")

	// ErrInvalidKeySize indicates that a key has an incompatible size or curve for its algorithm.
	ErrInvalidKeySize = errors.New("invalid key size")

	// ErrNoKeyProvided indicates that required key material was not supplied.
	ErrNoKeyProvided = errors.New("no key provided")

	// ErrInvalidSignature indicates that cryptographic signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrVerificationFailed indicates that verifying the selected signatures failed; it wraps the underlying error.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrContentDigestMismatch indicates that a covered Content-Digest does not match the message body.
	ErrContentDigestMismatch = errors.New("content digest mismatch")

	// ErrMalformedData indicates malformed signature or other structured HTTP message data.
	ErrMalformedData = errors.New("malformed data")

	// ErrUnsupportedComponentIdentifier indicates that a covered component identifier is unsupported.
	ErrUnsupportedComponentIdentifier = errors.New("unsupported component identifier")

	// ErrInvalidComponentIdentifier indicates malformed or invalid parameters on a component identifier.
	ErrInvalidComponentIdentifier = errors.New("invalid component identifier")

	// ErrCanonicalization indicates that a covered HTTP message component could not be canonicalized.
	ErrCanonicalization = errors.New("failed to canonicalize component")

	// ErrMalformedSignatureParameter indicates a signature parameter with an invalid type or value.
	ErrMalformedSignatureParameter = errors.New("malformed signature parameter")

	// ErrNoApplicableDigestFound indicates that no supported digest could be checked in Content-Digest.
	ErrNoApplicableDigestFound = errors.New("no applicable digest found")

	// ErrVerifierCreation indicates that the verifier configuration could not be constructed.
	ErrVerifierCreation = errors.New("verifier creation failed")

	// ErrParameter indicates a failed signature parameter check or invalid option.
	ErrParameter = errors.New("parameter error")

	// ErrValidity indicates that a signature failed its time validity checks.
	ErrValidity = errors.New("validity error")

	// ErrMissingParameter indicates that a required signature parameter or covered component is missing.
	ErrMissingParameter = errors.New("missing parameter error")

	// ErrSignatureNegotiationError indicates a failure while preparing signature negotiation.
	ErrSignatureNegotiationError = errors.New("signature negotiation error")
)

// NoApplicableSignatureError indicates that a message does not contain all
// required signatures or any signature selected by the verifier. If signature
// negotiation was configured, Negotiate can add the requested headers to a
// response. It can be recognized with errors.As or errors.Is.
type NoApplicableSignatureError struct {
	headerToAdd http.Header
}

// Error returns a description of the missing applicable signature.
func (e *NoApplicableSignatureError) Error() string { return "no applicable signature found" }

// Is matches another NoApplicableSignatureError for use with errors.Is.
func (e *NoApplicableSignatureError) Is(err error) bool {
	_, ok := err.(*NoApplicableSignatureError)

	return ok
}

// Negotiate appends any prepared Accept-Signature and related negotiation
// headers to header. If no negotiation was configured, it adds nothing.
// The caller must supply a writable, non-nil http.Header.
func (e *NoApplicableSignatureError) Negotiate(header http.Header) {
	for name, values := range e.headerToAdd {
		for _, value := range values {
			header.Add(name, value)
		}
	}
}

const (
	headerAcceptSignature   = "Accept-Signature"
	headerSignature         = "Signature"
	headerSignatureInput    = "Signature-Input"
	headerContentDigest     = "Content-Digest"
	headerWantContentDigest = "Want-Content-Digest"

	componentIdentifierContentDigest = "content-digest"
)

// SignatureAlgorithm identifies the concrete cryptographic algorithm used
// to create or verify an HTTP message signature. The supported algorithms
// are the constants below; the selected algorithm must be compatible with
// the supplied Key.Material.
type SignatureAlgorithm string

const (
	// RsaPkcs1v15Sha256 selects RSA PKCS#1 v1.5 with SHA-256.
	RsaPkcs1v15Sha256 SignatureAlgorithm = "rsa-v1_5-sha256"

	// RsaPkcs1v15Sha384 selects RSA PKCS#1 v1.5 with SHA-384.
	RsaPkcs1v15Sha384 SignatureAlgorithm = "rsa-v1_5-sha384"

	// RsaPkcs1v15Sha512 selects RSA PKCS#1 v1.5 with SHA-512.
	RsaPkcs1v15Sha512 SignatureAlgorithm = "rsa-v1_5-sha512"

	// RsaPssSha256 selects RSA-PSS with SHA-256.
	RsaPssSha256 SignatureAlgorithm = "rsa-pss-sha256"

	// RsaPssSha384 selects RSA-PSS with SHA-384.
	RsaPssSha384 SignatureAlgorithm = "rsa-pss-sha384"

	// RsaPssSha512 selects RSA-PSS with SHA-512.
	RsaPssSha512 SignatureAlgorithm = "rsa-pss-sha512"

	// EcdsaP256Sha256 selects ECDSA using P-256 and SHA-256.
	EcdsaP256Sha256 SignatureAlgorithm = "ecdsa-p256-sha256"

	// EcdsaP384Sha384 selects ECDSA using P-384 and SHA-384.
	EcdsaP384Sha384 SignatureAlgorithm = "ecdsa-p384-sha384"

	// EcdsaP521Sha512 selects ECDSA using P-521 and SHA-512.
	EcdsaP521Sha512 SignatureAlgorithm = "ecdsa-p521-sha512"

	// Ed25519 selects Ed25519 signatures.
	Ed25519 SignatureAlgorithm = "ed25519"

	// HmacSha256 selects HMAC with SHA-256.
	HmacSha256 SignatureAlgorithm = "hmac-sha256"

	// HmacSha384 selects HMAC with SHA-384.
	HmacSha384 SignatureAlgorithm = "hmac-sha384"

	// HmacSha512 selects HMAC with SHA-512.
	HmacSha512 SignatureAlgorithm = "hmac-sha512"
)

// DigestAlgorithm identifies a hash algorithm supported for HTTP Content-Digest
// generation and verification.
type DigestAlgorithm string

const (
	// Sha256 selects SHA-256.
	Sha256 DigestAlgorithm = "sha-256"

	// Sha512 selects SHA-512.
	Sha512 DigestAlgorithm = "sha-512"
)

// SignatureParameter names an RFC 9421 signature parameter or a
// profile-specific extension parameter.
type SignatureParameter string

const (
	// KeyID names the keyid signature parameter.
	KeyID SignatureParameter = "keyid"

	// Alg names the alg signature parameter.
	Alg SignatureParameter = "alg"

	// Created names the created timestamp parameter.
	Created SignatureParameter = "created"

	// Expires names the expires timestamp parameter.
	Expires SignatureParameter = "expires"

	// Nonce names the nonce signature parameter.
	Nonce SignatureParameter = "nonce"

	// Tag names the tag signature parameter.
	Tag SignatureParameter = "tag"
)

// SignatureParameters contains all signature parameters transmitted in a
// Signature-Input entry, including profile-specific extensions. Keys are the
// parameter names; values are decoded Structured Fields bare items (for
// example string, Token, int64, float64, bool, or []byte).
// Display Strings are exposed as ordinary strings.
type SignatureParameters map[SignatureParameter]any

// KeyID returns the keyid parameter if present and of the expected type.
func (p SignatureParameters) KeyID() (string, bool) {
	value, ok := p[KeyID].(string)

	return value, ok
}

// Alg returns the alg parameter if present and of the expected type.
func (p SignatureParameters) Alg() (SignatureAlgorithm, bool) {
	value, ok := p[Alg].(string)

	return SignatureAlgorithm(value), ok
}

// Created returns the created parameter as a Unix timestamp if it has the expected type.
func (p SignatureParameters) Created() (int64, bool) {
	value, ok := p[Created].(int64)

	return value, ok
}

// Expires returns the expires parameter as a Unix timestamp if it has the expected type.
func (p SignatureParameters) Expires() (int64, bool) {
	value, ok := p[Expires].(int64)

	return value, ok
}

// Nonce returns the nonce parameter if present and of the expected type.
func (p SignatureParameters) Nonce() (string, bool) {
	value, ok := p[Nonce].(string)

	return value, ok
}

// Tag returns the tag parameter if present and of the expected type.
func (p SignatureParameters) Tag() (string, bool) {
	value, ok := p[Tag].(string)

	return value, ok
}

// Token represents a Structured Fields token. It is distinct from string so
// applications can distinguish token values from quoted Structured Fields
// strings when validating profile-specific signature parameters.
type Token string

// Key combines cryptographic key material with the concrete signature
// algorithm to use. Signing requires private or symmetric key material;
// verification requires public or symmetric key material.
type Key struct {
	// Algorithm is the signature algorithm to use with Material.
	// It must be compatible with the supplied key material.
	Algorithm SignatureAlgorithm

	// Material is the private, public, or symmetric key material used by the
	// chosen algorithm. The currently supported implementations accept the
	// corresponding Go crypto key types or []byte for HMAC.
	Material any
}

// ResolveKey makes a statically configured Key usable as a KeyResolver.
func (k Key) ResolveKey(_ context.Context, _ SignatureInfo) (KeyInfo, error) {
	return KeyInfo{Key: k}, nil
}

// KeyInfo is returned by a KeyResolver and contains the accepted verification
// key and optional application-defined information about its resolution.
type KeyInfo struct {
	// Key is the trusted key and algorithm selected for this signature.
	Key Key
	// Metadata is application-specific information returned alongside the key.
	// It is passed through to VerifiedSignature only on successful verification.
	Metadata any
}

// SignatureInfo describes one signature being considered for verification.
// All its values are unverified and may be sender-controlled. The
// resolver implementation must treat them as untrusted input when selecting
// key material. The message and maps are shared with the verification process
// and must not be modified by the resolver (including mutable values within
// the maps).
type SignatureInfo struct {
	// Label is the current Signature-Input dictionary member name. It is not
	// signed and can be changed by intermediaries; it is only a technical
	// reference.
	Label string

	// Message is the HTTP message being verified. Not all of its fields are
	// necessarily covered by the signature, and it must not be modified.
	Message *Message

	// Components maps covered component identifiers to the canonicalized
	// values used to construct the signature base. It excludes the synthetic
	// @signature-params component. Identifier parameters are retained in keys.
	Components map[string]string

	// Parameters contains the transmitted, decoded signature parameters.
	Parameters SignatureParameters
}

// KeyResolver resolves a trusted verification key for a specific HTTP message
// signature.
type KeyResolver interface {
	// ResolveKey returns the trusted key and optional metadata for info.
	// It is called before cryptographic verification. SignatureInfo and its
	// Message contain unverified, sender-controlled data. The implementation
	// must not mutate SignatureInfo.Message, Components, Parameters, or their
	// mutable contents: these are shared with the verification process and, on
	// success, with VerifiedSignature.
	ResolveKey(ctx context.Context, info SignatureInfo) (KeyInfo, error)
}

// nolint: gochecknoglobals
var supportedAlgs = map[DigestAlgorithm]crypto.Hash{
	Sha256: crypto.SHA256,
	Sha512: crypto.SHA512,
}
