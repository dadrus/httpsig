package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewPayloadVerifier(t *testing.T) {
	t.Parallel()

	ek25519, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkp256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	k256 := make([]byte, 32)
	n, err := rand.Read(k256)
	require.NoError(t, err)
	require.Equal(t, len(k256), n)

	for uc, tc := range map[string]struct {
		key any
		alg SignatureAlgorithm
		typ any
		err error
	}{
		"unsupported algorithm": {key: "foo", err: ErrUnsupportedKeyType},
		"ed25519 verifier":      {key: ek25519, alg: Ed25519, typ: &ed25519Verifier{}},
		"rsa verifier":          {key: &pk2048.PublicKey, alg: RsaPssSha256, typ: &rsaVerifier{}},
		"ecdsa verifier":        {key: &pkp256.PublicKey, alg: EcdsaP256Sha256, typ: &ecdsaVerifier{}},
		"hmac verifier":         {key: k256, alg: HmacSha256, typ: &symmetricSigner{}},
		"message verifier":      {key: &MessageVerifierMock{}, alg: SignatureAlgorithm("custom-alg"), typ: &messageVerifierAdaptor{}},
	} {
		t.Run(uc, func(t *testing.T) {
			sig, err := newPayloadVerifier(tc.key, tc.alg)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				require.IsType(t, tc.typ, sig)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		resolver KeyResolver
		opts     []VerifierOption
		assert   func(t *testing.T, err error, v *verifier)
	}{
		"without key resolver": {
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "no key resolver")
			},
		},
		"with key resolver only": {
			resolver: &KeyResolverMock{},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "validation of all signatures disabled, but no signature tags specified")
			},
		},
		"with component identifiers configuration error": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithComponents("@foo"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "unsupported component identifier: @foo")
			},
		},
		"with empty required tag": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag(""),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "required tag must not be empty")
			},
		},
		"cannot verify and negotiate any possible signature": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithSignatureNegotiation(),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "verification and negotiation")
			},
		},
		"global parameter conflict with validation of all signatures": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithForbiddenParameters("created"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"with verification of all signatures enabled": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, v.validateAllSigs)
				assert.Len(t, v.tagPolicies, 1)
				assert.Contains(t, v.tagPolicies, "")
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
			},
		},
		"with tag specific options only": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test",
					WithValidityTolerance(1*time.Second),
					WithComponents("@status"),
				),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagPolicies, 1)
				assert.NotContains(t, v.tagPolicies, "")
				require.Contains(t, v.tagPolicies, "test")

				exp := v.tagPolicies["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 1*time.Second, *exp.tolerance)
			},
		},
		"with global defaults without signature negotiation": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test"),
				WithValidityTolerance(1 * time.Second),
				WithComponents("@status"),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagPolicies, 1)
				assert.NotContains(t, v.tagPolicies, "")
				require.Contains(t, v.tagPolicies, "test")

				exp := v.tagPolicies["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 1*time.Second, *exp.tolerance)
				assert.Nil(t, exp.asb)
			},
		},
		"with global defaults with signature negotiation": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test"),
				WithValidityTolerance(1 * time.Second),
				WithComponents("@status", "content-digest"),
				WithSignatureNegotiation(
					WithSignatureAlgorithm(RsaPssSha512),
					WithKeyID("bar"),
				),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagPolicies, 1)
				assert.NotContains(t, v.tagPolicies, "")
				require.Contains(t, v.tagPolicies, "test")

				exp := v.tagPolicies["test"]
				assert.Len(t, exp.identifiers, 2)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, "content-digest", exp.identifiers[1].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 1*time.Second, *exp.tolerance)
				require.NotNil(t, exp.asb)
				assert.Nil(t, exp.asb.nonceGetter)
				assert.Equal(t, "sig", exp.asb.label)
				assert.ElementsMatch(t, exp.asb.cdAlgPrefs, []string{"sha-256=5", "sha-512=10"})
				assert.Equal(t, RsaPssSha512, exp.asb.signatureAlgorithm)
				assert.Equal(t, "bar", exp.asb.keyID)
				assert.True(t, exp.asb.addCreatedTS)
				assert.True(t, exp.asb.addExpiresTS)
				assert.True(t, exp.asb.wantContentDigest)
				assert.Equal(t, "test", exp.asb.tag)
				assert.Equal(t, exp.identifiers, exp.asb.identifiers)
			},
		},
		"with all possible options": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test",
					WithValidityTolerance(1*time.Second),
					WithComponents("@status"),
				),
				WithValidityTolerance(1 * time.Minute),
				WithComponents("@method"),
				WithValidateAllSignatures(),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagPolicies, 2)

				require.Contains(t, v.tagPolicies, "")
				exp := v.tagPolicies[""]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@method", exp.identifiers[0].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 1*time.Minute, *exp.tolerance)

				require.Contains(t, v.tagPolicies, "test")
				exp = v.tagPolicies["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 1*time.Second, *exp.tolerance)
			},
		},
		"parameter rules inherited from global configuration": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithRequiredParameters("nonce"),
					WithParameter("audience", "service-a"),
				),
				WithForbiddenParameters("alg", "keyid"),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)

				exp := v.tagPolicies["profile"]
				assert.Equal(t, []SignatureParameter{Nonce}, exp.requiredParameters)
				assert.Equal(t, []SignatureParameter{Alg, KeyID}, exp.forbiddenParameters)
				assert.Equal(t, []parameterOption{{name: "audience", value: "service-a"}}, exp.expectedParameters)
			},
		},
		"identical global and tag-specific expectations are compatible": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithParameter("audience", "service-a"),
				WithRequiredTag("profile",
					WithParameter("audience", "service-a"),
					WithRequiredParameters("audience"),
				),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, v.tagPolicies["profile"].expectedParameters, 1)
			},
		},
		"global and tag-specific parameter conflict": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithRequiredParameters("nonce"),
				),
				WithForbiddenParameters("nonce"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"conflicting expected values": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithParameter("audience", "first"),
				),
				WithParameter("audience", "second"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"required tag cannot be forbidden": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithForbiddenParameters("tag"),
				),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"required timestamp cannot be forbidden": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile"),
				WithForbiddenParameters("created"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"optional timestamp may be forbidden": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile"),
				WithForbiddenParameters("created"),
				WithCreatedTimestamp(false),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []SignatureParameter{Created}, v.tagPolicies["profile"].forbiddenParameters)
			},
		},
		"invalid parameter name": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithRequiredParameters("not a name"),
				),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"unsupported expected standard parameter": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithParameter("alg", "ed25519"),
				),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"invalid expected nonce": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithParameter("nonce", ""),
				),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"duplicate negotiation parameter rejected": {
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithSignatureNegotiation(
						WithParameter("audience", "first"),
						WithParameter("audience", "second"),
					),
				),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			res, err := NewVerifier(tc.resolver, tc.opts...)

			var v *verifier
			if res != nil {
				v = res.(*verifier)
			}

			tc.assert(t, err, v)
		})
	}
}

func TestVerifierVerify(t *testing.T) {
	testURL, err := url.Parse("http://example.com/foo?param=Value&Pet=dog")
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(testPubKeyRSAPSS))
	require.NotNil(t, block, "failed to parse PEM block containing the public key")

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "could not decode test public key")

	tkRSAPSS, ok := key.(*rsa.PublicKey)
	require.True(t, ok)

	block, _ = pem.Decode([]byte(testPubKeyECCP256))
	require.NotNil(t, block, "failed to parse PEM block containing the public key")

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "could not decode test public key")

	tkECCP256, ok := key.(*ecdsa.PublicKey)
	require.True(t, ok)

	tkMAC, err := base64.StdEncoding.DecodeString(testSharedSecret)
	require.NoError(t, err, "could not decode test shared secret")

	block, _ = pem.Decode([]byte(testPubKeyEd25519))
	require.NotNil(t, block, "failed to parse PEM block containing the public key")

	key, err = x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "could not decode test public key")

	tkEd25519, ok := key.(ed25519.PublicKey)
	require.True(t, ok)

	for uc, tc := range map[string]struct {
		opts              []VerifierOption
		verifyOpts        []VerifyOption
		msg               *Message
		configureResolver func(t *testing.T, kr *KeyResolverMock)
		assert            func(t *testing.T, err error, results VerificationResult)
	}{
		"without signature-input header": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, &NoApplicableSignatureError{})
			},
		},
		"malformed signature-input header items definition": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=(,);created=1618884473;keyid="test"`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "unrecognized character")
			},
		},
		"malformed signature-input header parameter": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid=test`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "keyid")
			},
		},
		"without signature header": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "no signature present")
			},
		},
		"malformed signature header": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"()"},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "format")
			},
		},
		"no applicable signature present": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)

				var noSigErr *NoApplicableSignatureError
				require.ErrorAs(t, err, &noSigErr)

				hdr := make(http.Header)
				noSigErr.Negotiate(hdr)
				require.Empty(t, hdr)
			},
		},
		"signature base creation error": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=("@status");created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "@status not valid for requests")
			},
		},
		"key resolver error": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig" &&
							si.Message != nil &&
							len(si.Components) == 0 &&
							si.Parameters["keyid"] == "test" &&
							si.Parameters["created"] == int64(1618884473)
					})).
					Return(KeyInfo{}, errors.New("test error"))
			},
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "test error")
			},
		},
		"expired signature rejected before key resolution": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithValidityTolerance(1 * time.Second),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();expires=1618884470;keyid="test";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "expired")
			},
		},
		"missing required component rejected before key resolution": {
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithComponents("@method"),
				),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, &NoApplicableSignatureError{})
				require.Empty(t, results)
			},
		},
		"required extension missing before key resolution": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithRequiredParameters("nonce"),
				),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{Header: http.Header{
				"Signature-Input": {`sig=();tag="profile"`},
				"Signature":       {"sig=:dGVzdA==:"},
			}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.NotErrorIs(t, err, &NoApplicableSignatureError{})
				require.Empty(t, results)
			},
		},
		"forbidden parameter rejected before key resolution": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithForbiddenParameters("keyid", "alg"),
				),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{Header: http.Header{
				"Signature-Input": {`sig=();keyid="key";tag="profile"`},
				"Signature":       {"sig=:dGVzdA==:"},
			}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.Empty(t, results)
			},
		},
		"dynamic parameter expectation checked before key resolution": {
			opts: []VerifierOption{
				WithRequiredTag("profile"),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			verifyOpts: []VerifyOption{WithParameter("audience", "expected")},
			msg: &Message{Header: http.Header{
				"Signature-Input": {`sig=();tag="profile";audience="other"`},
				"Signature":       {"sig=:dGVzdA==:"},
			}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.Empty(t, results)
			},
		},
		"dynamic expectations cannot override static values": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithParameter("audience", "static"),
				),
			},
			verifyOpts:        []VerifyOption{WithParameter("audience", "dynamic")},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.Empty(t, results)
			},
		},
		"dynamic rules cannot forbid required timestamps": {
			opts: []VerifierOption{
				WithRequiredTag("profile"),
			},
			verifyOpts: []VerifyOption{
				WithForbiddenParameters("created"),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.Empty(t, results)
			},
		},
		"dynamic audience requested in negotiation": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithSignatureNegotiation(),
				),
			},
			verifyOpts: []VerifyOption{
				WithParameter("audience", "service-a"),
			},
			msg: &Message{Header: http.Header{
				"Signature-Input": {`sig=();created=1618884473;expires=1618884600;tag="profile"`},
				"Signature":       {"sig=:dGVzdA==:"},
			}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				var negotiation *NoApplicableSignatureError
				require.ErrorAs(t, err, &negotiation)
				require.Empty(t, results)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.Equal(t, `sig=();created;expires;tag="profile";audience="service-a"`, hdr.Get(headerAcceptSignature))
			},
		},
		"static audience requested for missing signature": {
			opts: []VerifierOption{
				WithParameter("audience", "service-a"),
				WithRequiredTag("profile",
					WithSignatureNegotiation(),
				),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				var negotiation *NoApplicableSignatureError
				require.ErrorAs(t, err, &negotiation)
				require.Empty(t, results)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.Equal(t, `sig=();created;expires;tag="profile";audience="service-a"`, hdr.Get(headerAcceptSignature))
			},
		},
		"expected nonce overrides negotiation getter": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithSignatureNegotiation(
						WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) {
							return "getter", errors.New("getter must not be called")
						})),
					),
				),
			},
			verifyOpts: []VerifyOption{
				WithParameter("nonce", "expected-nonce"),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				var negotiation *NoApplicableSignatureError
				require.ErrorAs(t, err, &negotiation)
				require.Empty(t, results)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.Equal(t, `sig=();created;expires;nonce="expected-nonce";tag="profile"`, hdr.Get(headerAcceptSignature))
			},
		},
		"dynamic expectations projected for all required tags": {
			opts: []VerifierOption{
				WithRequiredTag("first",
					WithSignatureNegotiation(),
				),
				WithRequiredTag("second",
					WithSignatureNegotiation(),
				),
			},
			verifyOpts: []VerifyOption{
				WithParameter("audience", "service-a"),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				var negotiation *NoApplicableSignatureError
				require.ErrorAs(t, err, &negotiation)
				require.Empty(t, results)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.ElementsMatch(t, []string{
					`sig=();created;expires;tag="first";audience="service-a"`,
					`sig=();created;expires;tag="second";audience="service-a"`,
				}, hdr.Values(headerAcceptSignature))
			},
		},
		"conflicting explicit negotiation parameter is rejected": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithParameter("audience", "expected"),
					WithSignatureNegotiation(
						WithParameter("audience", "builder"),
					),
				),
			},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrSignatureNegotiationError)
				require.ErrorIs(t, err, ErrParameter)
				require.Empty(t, results)
			},
		},
		"signature algorithm mismatch after key resolution": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();alg="ed25519"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, mock.Anything).
					Return(KeyInfo{Key: Key{Algorithm: HmacSha256, Material: []byte("test")}}, nil).
					Once()
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "key algorithm ed25519 does not match signature algorithm hmac-sha256")
				require.Empty(t, results)
			},
		},
		"unknown algorithm with message verifier": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Context:   context.Background(),
				IsRequest: true,
				Method:    http.MethodGet,
				Header: http.Header{
					"Signature-Input": []string{`sig=("@method");alg="custom-alg"`},
					"Signature":       []string{"sig=:AQID:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				mockVerifier := NewMessageVerifierMock(t)
				mockVerifier.EXPECT().VerifyMessage(
					context.Background(),
					[]byte("\"@method\": GET\n\"@signature-params\": (\"@method\");alg=\"custom-alg\""),
					[]byte{1, 2, 3},
				).Return(nil).Once()

				kr.EXPECT().ResolveKey(mock.Anything, mock.Anything).
					Return(KeyInfo{Key: Key{Algorithm: SignatureAlgorithm("custom-alg"), Material: mockVerifier}}, nil).Once()
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, results, 1)
				assert.Equal(t, "sig", results[0].Label)
			},
		},
		"unsupported signature key": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiresTimestamp(false),
				WithCreatedTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();keyid="test";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig" &&
							si.Message != nil &&
							len(si.Components) == 0 &&
							si.Parameters["keyid"] == "test" &&
							si.Parameters["tag"] == "foo"
					})).
					Return(KeyInfo{Key: Key{Material: &rsa.PrivateKey{}}}, nil)
			},
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "unsupported key")
			},
		},
		"invalid signature": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiresTimestamp(false),
				WithCreatedTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();keyid="test";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				pk2048, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig" &&
							si.Message != nil &&
							len(si.Components) == 0 &&
							si.Parameters["keyid"] == "test" &&
							si.Parameters["tag"] == "foo"
					})).
					Return(
						KeyInfo{
							Key: Key{Material: &pk2048.PublicKey, Algorithm: RsaPkcs1v15Sha512},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "invalid signature")
			},
		},
		"signature parameters negotiation for not present tagged signature": {
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithComponents("@method", "content-digest"),
					WithSignatureNegotiation(
						WithSignatureAlgorithm(RsaPssSha512),
						WithKeyID("test-key"),
						WithLabel("bar"),
						WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
						WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha256, 1}),
					),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				var targetErr *NoApplicableSignatureError

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &targetErr)

				hdr := make(http.Header)
				targetErr.Negotiate(hdr)

				require.Len(t, hdr, 2)
				assert.Equal(t, `bar=("@method" "content-digest");created;expires;keyid="test-key";alg="rsa-pss-sha512";nonce="abc";tag="foo"`, hdr.Get("Accept-Signature"))
				assert.ElementsMatch(t, hdr.Values("Want-Content-Digest"), []string{"sha-256=1"})
			},
		},
		"global content-digest requirement overridden for negotiated tag": {
			opts: []VerifierOption{
				WithComponents("content-digest"),
				WithSignatureNegotiation(),
				WithRequiredTag("foo",
					WithComponents("@method"),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				var negotiation *NoApplicableSignatureError

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &negotiation)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)

				assert.Equal(t, `sig=("@method");created;expires;tag="foo"`, hdr.Get(headerAcceptSignature))
				assert.Empty(t, hdr.Values(headerWantContentDigest))
			},
		},
		"signature negotiation without nonce getter omits nonce": {
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithComponents("@method"),
					WithSignatureNegotiation(
						WithLabel("foo-sig"),
					),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				var targetErr *NoApplicableSignatureError

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &targetErr)

				hdr := make(http.Header)
				targetErr.Negotiate(hdr)

				assert.Equal(t, `foo-sig=("@method");created;expires;tag="foo"`, hdr.Get(headerAcceptSignature))
			},
		},
		"signature parameters negotiation for present signature with missing expires parameters": {
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithSignatureNegotiation(
						WithSignatureAlgorithm(RsaPssSha512),
						WithKeyID("test-key"),
						WithLabel("bar"),
						WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
						WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha256, 1}),
					),
				),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":            []string{"example.com"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test-key";nonce="abc";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				var targetErr *NoApplicableSignatureError

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &targetErr)

				hdr := make(http.Header)
				targetErr.Negotiate(hdr)

				require.Len(t, hdr, 1)
				assert.Equal(t, `bar=();created;expires;keyid="test-key";alg="rsa-pss-sha512";nonce="abc";tag="foo"`, hdr.Get("Accept-Signature"))
			},
		},
		"signature parameters negotiation fails because of nonce error": {
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithComponents("@method"),
					WithSignatureNegotiation(
						WithSignatureAlgorithm(RsaPssSha512),
						WithKeyID("test-key"),
						WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "", errors.New("test error") })),
					),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.NotErrorIs(t, err, &NoApplicableSignatureError{})
				require.ErrorContains(t, err, "test error")
			},
		},
		"signature verification fails due to invalid second content digest": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":            []string{"example.com"},
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Content-Digest":  []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:, sha-256=:ayJoZWxsbyI6ICJ3b3JsZCJ9:"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`},
					"Signature":       []string{"sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrContentDigestMismatch)
			},
		},
		"B.2.1. minimal signature using rsa-pss-sha512": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-minimal-signature-using-rsa
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":            []string{"example.com"},
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Content-Digest":  []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`},
					"Signature":       []string{"sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:"},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b21" &&
							si.Message != nil &&
							si.Message.Header.Get("Content-Length") == "18" &&
							len(si.Components) == 0 &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key-rsa-pss" &&
							si.Parameters["nonce"] == "b3k2pp5k7z-50gnwp.yemd"
					})).
					Return(
						KeyInfo{
							Key:      Key{Material: tkRSAPSS, Algorithm: RsaPssSha512},
							Metadata: "foo",
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b21", sig.Label)

				assert.Empty(t, sig.Components)

				assert.Len(t, sig.Parameters, 3)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-rsa-pss", sig.Parameters["keyid"])
				assert.Equal(t, "b3k2pp5k7z-50gnwp.yemd", sig.Parameters["nonce"])

				assert.Equal(t, "foo", sig.Metadata)
			},
		},
		"B.2.2. selective covered components using rsa-pss-sha512": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-selective-covered-component
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":            []string{"example.com"},
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Content-Digest":  []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`},
					"Signature":       []string{"sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b22" &&
							si.Message != nil &&
							si.Message.Header.Get("Content-Length") == "18" &&
							len(si.Components) == 3 &&
							si.Components["@authority"] == "example.com" &&
							si.Components["@query-param;name=\"Pet\""] == "dog" &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key-rsa-pss" &&
							si.Parameters["tag"] == "header-example"
					})).
					Return(
						KeyInfo{
							Key:      Key{Material: tkRSAPSS, Algorithm: RsaPssSha512},
							Metadata: []string{"foo"},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b22", sig.Label)

				assert.Len(t, sig.Components, 3)
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "dog", sig.Components["@query-param;name=\"Pet\""])

				assert.Len(t, sig.Parameters, 3)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-rsa-pss", sig.Parameters["keyid"])
				assert.Equal(t, "header-example", sig.Parameters["tag"])

				assert.Equal(t, []string{"foo"}, sig.Metadata)
			},
		},
		"B.2.3. full coverage using rsa-pss-sha512": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-full-coverage-using-rsa-pss
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":            []string{"example.com"},
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Content-Digest":  []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`},
					"Signature":       []string{"sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b23" &&
							si.Message != nil &&
							si.Message.Header.Get("Content-Length") == "18" &&
							len(si.Components) == 8 &&
							si.Components["date"] == "Tue, 20 Apr 2021 02:07:55 GMT" &&
							si.Components["@method"] == "POST" &&
							si.Components["@path"] == "/foo" &&
							si.Components["@query"] == "?param=Value&Pet=dog" &&
							si.Components["@authority"] == "example.com" &&
							si.Components["content-type"] == "application/json" &&
							si.Components["content-digest"] == "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:" &&
							si.Components["content-length"] == "18" &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key-rsa-pss"
					})).
					Return(
						KeyInfo{
							Key: Key{Material: tkRSAPSS, Algorithm: RsaPssSha512},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b23", sig.Label)

				assert.Len(t, sig.Components, 8)
				assert.Equal(t, "Tue, 20 Apr 2021 02:07:55 GMT", sig.Components["date"])
				assert.Equal(t, "POST", sig.Components["@method"])
				assert.Equal(t, "/foo", sig.Components["@path"])
				assert.Equal(t, "?param=Value&Pet=dog", sig.Components["@query"])
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "application/json", sig.Components["content-type"])
				assert.Equal(t, "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:", sig.Components["content-digest"])
				assert.Equal(t, "18", sig.Components["content-length"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-rsa-pss", sig.Parameters["keyid"])

				assert.Nil(t, sig.Metadata)
			},
		},
		"B.2.4. signing a response using ecdsa-p256-sha256": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-response-using-ec
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:     http.MethodPost,
				StatusCode: 200,
				Authority:  "example.com",
				URL:        testURL,
				Header: http.Header{
					"Content-Type":    []string{"application/json"},
					"Content-Digest":  []string{"sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
					"Content-Length":  []string{"23"},
					"Signature-Input": []string{`sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`},
					"Signature":       []string{"sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:"},
				},
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"message": "good dog"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b24" &&
							si.Message != nil &&
							len(si.Components) == 4 &&
							si.Components["@status"] == "200" &&
							si.Components["content-type"] == "application/json" &&
							si.Components["content-digest"] == "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:" &&
							si.Components["content-length"] == "23" &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key-ecc-p256"
					})).
					Return(
						KeyInfo{
							Key:      Key{Material: tkECCP256, Algorithm: EcdsaP256Sha256},
							Metadata: map[string]int{"foo": 1},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b24", sig.Label)

				assert.Len(t, sig.Components, 4)
				assert.Equal(t, "200", sig.Components["@status"])
				assert.Equal(t, "application/json", sig.Components["content-type"])
				assert.Equal(t, "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:", sig.Components["content-digest"])
				assert.Equal(t, "23", sig.Components["content-length"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-ecc-p256", sig.Parameters["keyid"])

				assert.Equal(t, map[string]int{"foo": 1}, sig.Metadata)
			},
		},
		"B.2.5. signing a request using hmac-sha256": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-hma
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Signature-Input": []string{`sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`},
					"Signature":       []string{"sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b25" &&
							si.Message != nil &&
							len(si.Components) == 3 &&
							si.Components["date"] == "Tue, 20 Apr 2021 02:07:55 GMT" &&
							si.Components["@authority"] == "example.com" &&
							si.Components["content-type"] == "application/json" &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-shared-secret"
					})).
					Return(
						KeyInfo{
							Key: Key{Material: tkMAC, Algorithm: HmacSha256},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b25", sig.Label)

				assert.Len(t, sig.Components, 3)
				assert.Equal(t, "Tue, 20 Apr 2021 02:07:55 GMT", sig.Components["date"])
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "application/json", sig.Components["content-type"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-shared-secret", sig.Parameters["keyid"])

				assert.Empty(t, sig.Metadata)
			},
		},
		"B.2.6. signing a request using ed25519": {
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-ed2
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestamp(false),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Date":            []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":    []string{"application/json"},
					"Content-Length":  []string{"18"},
					"Signature-Input": []string{`sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`},
					"Signature":       []string{"sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig-b26" &&
							si.Message != nil &&
							len(si.Components) == 6 &&
							si.Components["date"] == "Tue, 20 Apr 2021 02:07:55 GMT" &&
							si.Components["@method"] == "POST" &&
							si.Components["@path"] == "/foo" &&
							si.Components["@authority"] == "example.com" &&
							si.Components["content-type"] == "application/json" &&
							si.Components["content-length"] == "18" &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key-ed25519"
					})).
					Return(
						KeyInfo{
							Key: Key{Material: tkEd25519, Algorithm: Ed25519},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "sig-b26", sig.Label)

				assert.Len(t, sig.Components, 6)
				assert.Equal(t, "Tue, 20 Apr 2021 02:07:55 GMT", sig.Components["date"])
				assert.Equal(t, "POST", sig.Components["@method"])
				assert.Equal(t, "/foo", sig.Components["@path"])
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "application/json", sig.Components["content-type"])
				assert.Equal(t, "18", sig.Components["content-length"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-ed25519", sig.Parameters["keyid"])

				assert.Empty(t, sig.Metadata)
			},
		},
		"invalid untagged signature is ignored": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{
						`valid=();created=1618884473;keyid="test-shared-secret";tag="foo", ` +
							`invalid=();created=1618884473;keyid="test-shared-secret"`,
					},
					"Signature": []string{
						`valid=:VhBIZ0nP4o+r4bSKCvC+gc0VI1yVhhN1PECWW8ZF2Dg=:, ` +
							`invalid=:dGVzdA==:`,
					},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, mock.Anything).
					Return(
						KeyInfo{
							Key:      Key{Material: tkMAC, Algorithm: HmacSha256},
							Metadata: map[string]string{"foo": "bar"},
						},
						nil,
					).Once()
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)

				require.Len(t, results, 1)

				sig := results[0]
				assert.Equal(t, "valid", sig.Label)

				assert.Empty(t, sig.Components)

				assert.Len(t, sig.Parameters, 3)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-shared-secret", sig.Parameters["keyid"])
				assert.Equal(t, "foo", sig.Parameters["tag"])

				assert.Equal(t, map[string]string{"foo": "bar"}, sig.Metadata)
			},
		},
		"invalid untagged signature fails when validating all": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{
						`valid=();created=1618884473;keyid="test-shared-secret";tag="foo", ` +
							`invalid=();created=1618884473;keyid="test-shared-secret"`,
					},
					"Signature": []string{
						`valid=:VhBIZ0nP4o+r4bSKCvC+gc0VI1yVhhN1PECWW8ZF2Dg=:, ` +
							`invalid=:dGVzdA==:`,
					},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, mock.Anything).
					Return(
						KeyInfo{
							Key: Key{Material: tkMAC, Algorithm: HmacSha256},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrInvalidSignature)

				require.Empty(t, results)
			},
		},
		"multiple valid signatures with different keys and metadata": {
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithExpiresTimestamp(false),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Length": []string{"18"},
					"Signature-Input": []string{
						`first=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret", ` +
							`second=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
					},
					"Signature": []string{
						`first=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:, ` +
							`second=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:`,
					},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "first" &&
							si.Parameters["keyid"] == "test-shared-secret" &&
							si.Components["date"] == "Tue, 20 Apr 2021 02:07:55 GMT" &&
							si.Components["@authority"] == "example.com" &&
							si.Components["content-type"] == "application/json"
					})).
					Return(KeyInfo{
						Key:      Key{Material: tkMAC, Algorithm: HmacSha256},
						Metadata: "hmac",
					}, nil).
					Once()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "second" &&
							si.Parameters["keyid"] == "test-key-ed25519" &&
							si.Components["@method"] == "POST" &&
							si.Components["@path"] == "/foo" &&
							si.Components["@authority"] == "example.com"
					})).
					Return(KeyInfo{
						Key:      Key{Material: tkEd25519, Algorithm: Ed25519},
						Metadata: "ed25519",
					}, nil).
					Once()
			},
			assert: func(t *testing.T, err error, results VerificationResult) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, results, 2)

				idx := slices.IndexFunc(results, func(sig VerifiedSignature) bool {
					return sig.Label == "first"
				})
				require.NotEqual(t, -1, idx, "signature with label first not found")

				sig := results[idx]
				assert.Equal(t, "first", sig.Label)

				assert.Len(t, sig.Components, 3)
				assert.Equal(t, "Tue, 20 Apr 2021 02:07:55 GMT", sig.Components["date"])
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "application/json", sig.Components["content-type"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-shared-secret", sig.Parameters["keyid"])

				assert.Equal(t, "hmac", sig.Metadata)

				idx = slices.IndexFunc(results, func(sig VerifiedSignature) bool {
					return sig.Label == "second"
				})
				require.NotEqual(t, -1, idx, "signature with label second not found")

				sig = results[idx]
				assert.Equal(t, "second", sig.Label)

				assert.Len(t, sig.Components, 6)
				assert.Equal(t, "Tue, 20 Apr 2021 02:07:55 GMT", sig.Components["date"])
				assert.Equal(t, "POST", sig.Components["@method"])
				assert.Equal(t, "/foo", sig.Components["@path"])
				assert.Equal(t, "example.com", sig.Components["@authority"])
				assert.Equal(t, "application/json", sig.Components["content-type"])
				assert.Equal(t, "18", sig.Components["content-length"])

				assert.Len(t, sig.Parameters, 2)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-key-ed25519", sig.Parameters["keyid"])

				assert.Equal(t, "ed25519", sig.Metadata)
			},
		},
		"tag-specific negotiation": {
			opts: []VerifierOption{
				WithRequiredTag("profile",
					WithSignatureNegotiation(
						WithParameter("audience", "service-a"),
						WithParameter("challenge", Token("example")),
					),
				),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header:    http.Header{},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)

				var negotiation *NoApplicableSignatureError

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &negotiation)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.Equal(t, `sig=();created;expires;tag="profile";audience="service-a";challenge=example`, hdr.Get(headerAcceptSignature))
			},
		},
		"inherited global negotiation": {
			opts: []VerifierOption{
				WithSignatureNegotiation(
					WithParameter("audience", "service-a"),
				),
				WithRequiredTag("profile"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header:    http.Header{},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)

				var negotiation *NoApplicableSignatureError

				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &negotiation)

				hdr := make(http.Header)
				negotiation.Negotiate(hdr)
				assert.Equal(t, `sig=();created;expires;tag="profile";audience="service-a"`, hdr.Get(headerAcceptSignature))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			withRFC9421Time(t, func(t *testing.T) {
				t.Helper()

				kr := NewKeyResolverMock(t)
				tc.configureResolver(t, kr)

				v, err := NewVerifier(kr, tc.opts...)
				require.NoError(t, err)

				results, err := v.Verify(tc.msg, tc.verifyOpts...)
				tc.assert(t, err, results)
			})
		})
	}

	t.Run("signed extensions with static and dynamic requirements", func(t *testing.T) {
		key := Key{Algorithm: HmacSha256, Material: []byte("secret")}
		inputBytes := []byte("data")
		signer, err := NewSigner(key,
			WithTag("profile"),
			WithComponents("@method"),
			WithParameter("audience", "service-a"),
			WithParameter("score", 1.2349),
			WithParameter("mode", Token("example")),
			WithParameter("flag", true),
			WithParameter("opaque", inputBytes),
		)
		require.NoError(t, err)

		msg := &Message{
			Context:   context.Background(),
			Header:    make(http.Header),
			Method:    http.MethodGet,
			Authority: "example.com",
			URL:       testURL,
			IsRequest: true,
		}
		_, err = signer.Sign(msg, WithParameter("nonce", "request-nonce"))
		require.NoError(t, err)

		ver, err := NewVerifier(key,
			WithRequiredTag("profile",
				WithComponents("@method"),
				WithRequiredParameters("nonce"),
				WithForbiddenParameters("keyid", "alg"),
				WithParameter("score", 1.2349),
				WithParameter("mode", Token("example")),
				WithParameter("flag", true),
				WithParameter("opaque", inputBytes),
			),
		)
		require.NoError(t, err)

		inputBytes[0] = 'X' // Neither signer nor verifier may retain this mutable input.

		for _, opts := range [][]VerifyOption{
			{
				WithParameter("audience", "service-a"),
			},
			{
				WithParameter("audience", "service-a"),
				WithRequiredParameters("mode"),
			},
			nil,
		} {
			results, err := ver.Verify(msg, opts...)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, "service-a", results[0].Parameters["audience"])
		}

		_, err = ver.Verify(msg, WithParameter("audience", "other"))
		require.ErrorIs(t, err, ErrParameter)

		results, err := ver.Verify(msg)
		require.NoError(t, err)
		require.Len(t, results, 1) // A failed per-call override did not mutate the verifier.

		_, err = ver.Verify(msg, WithForbiddenParameters("nonce"))
		require.ErrorIs(t, err, ErrParameter)

		// A Structured-Fields Token is not interchangeable with a String.
		withString, err := NewVerifier(key,
			WithRequiredTag("profile",
				WithParameter("mode", "example"),
			),
		)
		require.NoError(t, err)
		_, err = withString.Verify(msg)
		require.ErrorIs(t, err, ErrParameter)

		var wg sync.WaitGroup

		errors := make(chan error, 16)

		for range 16 {
			wg.Go(func() {
				_, err := ver.Verify(msg, WithParameter("audience", "service-a"))
				errors <- err
			})
		}

		wg.Wait()
		close(errors)

		for err := range errors {
			require.NoError(t, err)
		}
	})
}

func TestVerifierApplicableSignatures(t *testing.T) {
	t.Parallel()

	withTag := func(tag string) *signatureInput {
		params := httpsfv.NewParams()
		params.Add(string(Tag), tag)

		return newSignatureInput(nil, params)
	}

	for uc, tc := range map[string]struct {
		verifier verifier
		refs     map[string]*signatureInput
		assert   func(t *testing.T, err error, refs map[string]*signatureInput)
	}{
		"only required signatures are applicable": {
			verifier: verifier{
				tagPolicies: map[string]*verificationPolicy{"foo": {}},
			},
			refs: map[string]*signatureInput{
				"matching": withTag("foo"),
				"other":    withTag("bar"),
				"empty":    withTag(""),
				"untagged": newSignatureInput(nil, nil),
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, refs, 1)
				assert.Contains(t, refs, "matching")
			},
		},
		"no matching signature": {
			verifier: verifier{
				tagPolicies: map[string]*verificationPolicy{"foo": {}},
			},
			refs: map[string]*signatureInput{
				"other": withTag("bar"),
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.ErrorIs(t, err, &NoApplicableSignatureError{})
				assert.Nil(t, refs)
			},
		},
		"missing tag": {
			verifier: verifier{
				tagPolicies: map[string]*verificationPolicy{"foo": {}},
			},
			refs: map[string]*signatureInput{
				"untagged": newSignatureInput(nil, nil),
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.ErrorIs(t, err, &NoApplicableSignatureError{})
				assert.Nil(t, refs)
			},
		},
		"all signatures are applicable": {
			verifier: verifier{
				validateAllSigs: true,
			},
			refs: map[string]*signatureInput{
				"tagged":   withTag("foo"),
				"empty":    withTag(""),
				"untagged": newSignatureInput(nil, nil),
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, refs, 3)
				assert.Contains(t, refs, "tagged")
				assert.Contains(t, refs, "empty")
				assert.Contains(t, refs, "untagged")
			},
		},
		"validate all with required tag": {
			verifier: verifier{
				validateAllSigs: true,
				tagPolicies:     map[string]*verificationPolicy{"foo": {}},
			},
			refs: map[string]*signatureInput{
				"matching": withTag("foo"),
				"other":    withTag("bar"),
				"untagged": newSignatureInput(nil, nil),
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.NoError(t, err)
				assert.Len(t, refs, 3)
				assert.Contains(t, refs, "matching")
				assert.Contains(t, refs, "other")
				assert.Contains(t, refs, "untagged")
			},
		},
		"no signatures": {
			verifier: verifier{
				validateAllSigs: true,
			},
			assert: func(t *testing.T, err error, refs map[string]*signatureInput) {
				t.Helper()

				require.ErrorIs(t, err, &NoApplicableSignatureError{})
				assert.Nil(t, refs)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			v := tc.verifier

			refs, err := v.applicableSignatures(tc.refs)

			tc.assert(t, err, refs)
		})
	}
}
