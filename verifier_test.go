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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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

	for _, tc := range []struct {
		uc  string
		key any
		alg SignatureAlgorithm
		typ any
		err error
	}{
		{uc: "unsupported algorithm", key: "foo", err: ErrUnsupportedKeyType},
		{uc: "ed25519 verifier", key: ek25519, alg: Ed25519, typ: &ed25519Verifier{}},
		{uc: "rsa verifier", key: &pk2048.PublicKey, alg: RsaPssSha256, typ: &rsaVerifier{}},
		{uc: "ecdsa verifier", key: &pkp256.PublicKey, alg: EcdsaP256Sha256, typ: &ecdsaVerifier{}},
		{uc: "hmac verifier", key: k256, alg: HmacSha256, typ: &symmetricSigner{}},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newPayloadVerifier(tc.key, "test", tc.alg)

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

func TestWithRequiredComponents(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		identifiers []string
		err         error
	}{
		{uc: "multiple valid identifier", identifiers: []string{"@status;req", "@method"}},
		{uc: "invalid identifier", identifiers: []string{"@foo"}, err: ErrUnsupportedComponentIdentifier},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			v := &verifier{}
			exp := &expectations{}

			err := WithRequiredComponents(tc.identifiers...)(v, exp, false)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Empty(t, v.tagExpectations)
				require.Len(t, exp.identifiers, len(tc.identifiers))

				for i, id := range exp.identifiers {
					vals := strings.Split(tc.identifiers[i], ";")
					assert.Equal(t, vals[0], id.Value)
				}
			}
		})
	}
}

func TestWithValidityTolerance(t *testing.T) {
	t.Parallel()

	v := &verifier{}
	exp := &expectations{}

	err := WithValidityTolerance(1*time.Minute)(v, exp, false)
	require.NoError(t, err)

	assert.Empty(t, v.tagExpectations)
	assert.Equal(t, 1*time.Minute, exp.tolerance)
}

func TestWithRequiredTag(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opts   []VerifierOption
		assert func(t *testing.T, err error, exp *expectations)
	}{
		{
			uc: "without options",
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Empty(t, exp.identifiers)
				assert.Equal(t, time.Duration(-1), exp.tolerance) //nolint:testifylint
			},
		},
		{
			uc: "with identifiers only",
			opts: []VerifierOption{
				WithRequiredComponents("@status"),
			},
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, time.Duration(-1), exp.tolerance) //nolint:testifylint
			},
		},
		{
			uc: "with tolerance only",
			opts: []VerifierOption{
				WithValidityTolerance(5 * time.Minute),
			},
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Empty(t, exp.identifiers)
				assert.Equal(t, 5*time.Minute, exp.tolerance)
			},
		},
		{
			uc: "with all possible options",
			opts: []VerifierOption{
				WithRequiredComponents("@status"),
				WithValidityTolerance(5 * time.Minute),
			},
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, 5*time.Minute, exp.tolerance)
			},
		},
		{
			uc: "with unsupported identifier",
			opts: []VerifierOption{
				WithRequiredComponents("@foo"),
			},
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.Nil(t, exp)
			},
		},
		{
			uc: "with nested WithRequiredTag",
			opts: []VerifierOption{
				WithRequiredTag("foo"),
			},
			assert: func(t *testing.T, err error, _ *expectations) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "WithRequiredTag")
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			v := &verifier{tagExpectations: make(map[string]*expectations)}

			recoverIfPanics := func(t *testing.T, f func() error) (err error) {
				t.Helper()

				defer func() {
					var ok bool

					if res := recover(); res != nil {
						if err, ok = res.(error); !ok {
							err = fmt.Errorf("%v", res)
						}
					}
				}()

				err = f()

				return
			}

			err := recoverIfPanics(t, func() error {
				return WithRequiredTag("test", tc.opts...)(v, nil, false)
			})

			if err == nil {
				require.Len(t, v.tagExpectations, 1)
			}

			tc.assert(t, err, v.tagExpectations["test"])
		})
	}
}

func TestWithMaxAge(t *testing.T) {
	t.Parallel()

	v := &verifier{}
	exp := &expectations{}

	err := WithMaxAge(15*time.Minute)(v, exp, false)
	require.NoError(t, err)

	assert.Equal(t, 15*time.Minute, exp.maxAge)
}

func TestWithNonceChecker(t *testing.T) {
	t.Parallel()

	v := &verifier{}
	exp := &expectations{}
	storage := &NonceCheckerMock{}

	err := WithNonceChecker(storage)(v, exp, false)
	require.NoError(t, err)

	assert.Equal(t, storage, v.nonceChecker)
}

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc       string
		resolver KeyResolver
		opts     []VerifierOption
		assert   func(t *testing.T, err error, v *verifier)
	}{
		{
			uc: "without key resolver",
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "no key resolver")
			},
		},
		{
			uc:       "with key resolver only",
			resolver: &KeyResolverMock{},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "validation of all signatures disabled, but no signature tags specified")
			},
		},
		{
			uc:       "with option configuration error",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredComponents("@foo"),
			},
			assert: func(t *testing.T, err error, _ *verifier) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerifierCreation)
				require.ErrorContains(t, err, "unsupported component identifier: @foo")
			},
		},
		{
			uc:       "with verification of all signatures enabled",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithValidateAllSignatures(),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, v.validateAllSigs)
				assert.Len(t, v.tagExpectations, 1)
				assert.Contains(t, v.tagExpectations, "")
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
			},
		},
		{
			uc:       "with tag specific options only",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test",
					WithValidityTolerance(1*time.Second),
					WithRequiredComponents("@status"),
				),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagExpectations, 1)
				assert.NotContains(t, v.tagExpectations, "")
				require.Contains(t, v.tagExpectations, "test")

				exp := v.tagExpectations["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, 1*time.Second, exp.tolerance)
			},
		},
		{
			uc:       "with global defaults",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test"),
				WithValidityTolerance(1 * time.Second),
				WithRequiredComponents("@status"),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagExpectations, 1)
				assert.NotContains(t, v.tagExpectations, "")
				require.Contains(t, v.tagExpectations, "test")

				exp := v.tagExpectations["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, 1*time.Second, exp.tolerance)
			},
		},
		{
			uc:       "with all possible options",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test",
					WithValidityTolerance(1*time.Second),
					WithRequiredComponents("@status"),
				),
				WithValidityTolerance(1 * time.Minute),
				WithRequiredComponents("@method"),
				WithValidateAllSignatures(),
			},
			assert: func(t *testing.T, err error, v *verifier) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, v.validateAllSigs)
				assert.IsType(t, &KeyResolverMock{}, v.keyResolver)
				assert.Len(t, v.tagExpectations, 2)

				require.Contains(t, v.tagExpectations, "")
				exp := v.tagExpectations[""]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@method", exp.identifiers[0].Value)
				assert.Equal(t, 1*time.Minute, exp.tolerance)

				require.Contains(t, v.tagExpectations, "test")
				exp = v.tagExpectations["test"]
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, 1*time.Second, exp.tolerance)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
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
	// used by RFC9421 in test vectors
	currentTime = func() time.Time { return time.Unix(1618884473, 0) }

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

	for _, tc := range []struct {
		uc                string
		opts              []VerifierOption
		msg               *Message
		configureResolver func(t *testing.T, kr *KeyResolverMock)
		assert            func(t *testing.T, err error)
	}{
		{
			uc:                "without signature-input header",
			opts:              []VerifierOption{WithValidateAllSignatures()},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, &NoApplicableSignatureError{})
			},
		},
		{
			uc:   "malformed signature-input header items definition",
			opts: []VerifierOption{WithValidateAllSignatures()},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=(,);created=1618884473;keyid="test"`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "unrecognized character")
			},
		},
		{
			uc:   "malformed signature-input header parameter",
			opts: []VerifierOption{WithValidateAllSignatures()},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid=test`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "keyid")
			},
		},
		{
			uc:   "without signature header",
			opts: []VerifierOption{WithValidateAllSignatures()},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "no signature present")
			},
		},
		{
			uc:   "malformed signature header",
			opts: []VerifierOption{WithRequiredTag("foo")},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"()"},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "format")
			},
		},
		{
			uc:   "no applicable signature present",
			opts: []VerifierOption{WithRequiredTag("foo")},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, &NoApplicableSignatureError{})
			},
		},
		{
			uc:   "signature base creation error",
			opts: []VerifierOption{WithValidateAllSignatures()},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=("@status");created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
				IsRequest: true,
			},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "@status not valid for requests")
			},
		},
		{
			uc:   "key resolver error",
			opts: []VerifierOption{WithValidateAllSignatures()},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();created=1618884473;keyid="test"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, "test").Return(Key{}, errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "test error")
			},
		},
		{
			uc:   "signature parameters assertion error",
			opts: []VerifierOption{WithRequiredTag("foo"), WithValidityTolerance(1 * time.Second)},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();expires=1618884470;keyid="test";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, "test").Return(Key{}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "expired")
			},
		},
		{
			uc: "unsupported signature key",
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiredTimestampRequired(false),
				WithCreatedTimestampRequired(false),
			},
			msg: &Message{
				Header: http.Header{
					"Signature-Input": []string{`sig=();keyid="test";tag="foo"`},
					"Signature":       []string{"sig=:dGVzdA==:"},
				},
			},
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything, "test").Return(Key{Key: &rsa.PrivateKey{}}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "unsupported key")
			},
		},
		{
			uc: "invalid signature",
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiredTimestampRequired(false),
				WithCreatedTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test").Return(
					Key{Key: &pk2048.PublicKey, KeyID: "test", Algorithm: RsaPkcs1v15Sha512}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "invalid signature")
			},
		},
		{
			uc: "signature parameters negotiation",
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithRequiredComponents("@method"),
					WithSignatureNegotiationIfNotPresent(
						WithExpectedKey(Key{KeyID: "test-key", Algorithm: RsaPssSha512}),
						WithExpectedLabel("bar"),
						WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
					),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				var targetErr *NoApplicableSignatureError

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorAs(t, err, &targetErr)

				hdr := make(http.Header)
				targetErr.Negotiate(hdr)

				require.Len(t, hdr, 1)
				assert.Contains(t, hdr, "Accept-Signature")
				assert.Equal(t, `bar=("@method");created;expires;keyid="test-key";alg="rsa-pss-sha512";nonce="abc";tag="foo"`, hdr.Get("Accept-Signature"))
			},
		},
		{
			uc: "signature parameters negotiation fails because of nonce error",
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithRequiredComponents("@method"),
					WithSignatureNegotiationIfNotPresent(
						WithExpectedKey(Key{KeyID: "test-key", Algorithm: RsaPssSha512}),
						WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", errors.New("test error") })),
					),
				),
			},
			msg:               &Message{Header: http.Header{}},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.NotErrorIs(t, err, &NoApplicableSignatureError{})
				require.ErrorContains(t, err, "test error")
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-minimal-signature-using-rsa
			uc: "B.2.1. minimal signature using rsa-pss-sha512",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-key-rsa-pss").Return(
					Key{Key: tkRSAPSS, KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-selective-covered-component
			uc: "B.2.2. selective covered components using rsa-pss-sha512",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-key-rsa-pss").Return(
					Key{Key: tkRSAPSS, KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-full-coverage-using-rsa-pss
			uc: "B.2.3. full coverage using rsa-pss-sha512",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-key-rsa-pss").Return(
					Key{Key: tkRSAPSS, KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-response-using-ec
			uc: "B.2.4. signing a response using ecdsa-p256-sha256 ",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-key-ecc-p256").Return(
					Key{KeyID: "test-key-ecc-p256", Algorithm: EcdsaP256Sha256, Key: tkECCP256}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-hma
			uc: "B.2.5. signing a request using hmac-sha256",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-shared-secret").Return(
					Key{KeyID: "test-shared-secret", Algorithm: HmacSha256, Key: tkMAC}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-ed2
			uc: "B.2.6. signing a request using ed25519",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithCreatedTimestampRequired(false),
				WithExpiredTimestampRequired(false),
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

				kr.EXPECT().ResolveKey(mock.Anything, "test-key-ed25519").Return(
					Key{KeyID: "test-key-ed25519", Algorithm: Ed25519, Key: tkEd25519}, nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			kr := NewKeyResolverMock(t)
			tc.configureResolver(t, kr)

			v, err := NewVerifier(kr, tc.opts...)
			require.NoError(t, err)

			err = v.Verify(tc.msg)
			tc.assert(t, err)
		})
	}
}
