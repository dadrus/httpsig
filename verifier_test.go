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
	"slices"
	"strings"
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

func TestExpectationsAssertParameters(t *testing.T) {
	now := time.Now().UTC()
	falseVal := false
	trueVal := true
	noNonce := NonceValue{Present: false, Value: ""}

	for _, tc := range []struct {
		uc        string
		params    httpsfv.InnerList
		exp       expectations
		expAlg    SignatureAlgorithm
		configure func(t *testing.T, nc *NonceCheckerMock)
		assert    func(t *testing.T, err error)
	}{
		{
			uc: "replay attack",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Nonce), "test")

					return params
				}(),
			},
			exp: expectations{reqExpiresTS: &falseVal, reqCreatedTS: &falseVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nonce := NonceValue{
					Present: true,
					Value:   "test",
				}
				nc.EXPECT().CheckNonce(mock.Anything, nonce).Return(errors.New("test error"))
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "nonce validation failed")
			},
		},
		{
			uc: "signature algorithm mismatch",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Alg), string(RsaPssSha512))

					return params
				}(),
			},
			expAlg: EcdsaP256Sha256,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "key algorithm rsa-pss-sha512 does not match signature algorithm ecdsa-p256-sha256")
			},
		},
		{
			uc: "signature expired, no tolerance specified",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{reqExpiresTS: &falseVal, reqCreatedTS: &falseVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "expired")
			},
		},
		{
			uc: "signature is still valid with specified tolerance",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{
				tolerance:    3 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature is valid if expires in the future",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{
				tolerance:    2 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature not yet valid, no tolerance specified",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{reqCreatedTS: &falseVal, reqExpiresTS: &falseVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "not yet valid")
			},
		},
		{
			uc: "signature already valid with specified tolerance",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{
				tolerance:    3 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature is valid if created in the past",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{
				maxAge:       30 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "signature too old",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: expectations{reqCreatedTS: &falseVal, reqExpiresTS: &falseVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "too old")
			},
		},
		{
			uc:     "expected component identifier missing",
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp: func() expectations {
				ids, err := toComponentIdentifiers([]string{"@method;req", "@authority"})
				require.NoError(t, err)

				return expectations{identifiers: ids, reqCreatedTS: &falseVal, reqExpiresTS: &falseVal}
			}(),
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `"@method";req, "@authority"`)
			},
		},
		{
			uc:     "expected created parameter is missing",
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp:    expectations{reqCreatedTS: &trueVal, reqExpiresTS: &falseVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `created parameter`)
			},
		},
		{
			uc:     "expected expires parameter is missing",
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp:    expectations{reqCreatedTS: &falseVal, reqExpiresTS: &trueVal},
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nc.EXPECT().CheckNonce(mock.Anything, noNonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `expires parameter`)
			},
		},
		{
			uc: "successful assertion with all possible parameters",
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-3*time.Second).Unix())
					params.Add(string(Expires), now.Add(3*time.Second).Unix())
					params.Add(string(Alg), string(EcdsaP256Sha256))
					params.Add(string(KeyID), "test")
					params.Add(string(Nonce), "foo")
					params.Add(string(Tag), "test")

					return params
				}(),
				Items: []httpsfv.Item{
					httpsfv.NewItem("@method"),
					httpsfv.NewItem("@authority"),
				},
			},
			exp: func() expectations {
				ids, err := toComponentIdentifiers([]string{"@authority", "@method"})
				require.NoError(t, err)

				return expectations{
					identifiers: ids,
					maxAge:      5 * time.Second,
				}
			}(),
			expAlg: EcdsaP256Sha256,
			configure: func(t *testing.T, nc *NonceCheckerMock) {
				t.Helper()

				nonce := NonceValue{Present: true, Value: "foo"}
				nc.EXPECT().CheckNonce(mock.Anything, nonce).Return(nil)
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			msg := &Message{Context: context.TODO()}

			si, err := parseSignatureInput(tc.params)
			require.NoError(t, err)

			nc := NewNonceCheckerMock(t)
			tc.configure(t, nc)

			err = tc.exp.assert(si, msg, tc.expAlg, nc)

			tc.assert(t, err)
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

	t.Run("with duplicate WithRequiredTag", func(t *testing.T) {
		v := &verifier{tagExpectations: map[string]*expectations{"foo": {}}}

		err := WithRequiredTag("foo", nil)(v, nil, false)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrParameter)
		require.ErrorContains(t, err, "already configured")
	})
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

func TestWithSignatureNegotiation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opts   []SignatureNegotiationOption
		assert func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		{
			uc: "without options",
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, asb)
				assert.IsType(t, nonceGetter{}, asb.nonceGetter)
				assert.Equal(t, "sig", asb.label)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{"sha-256=5", "sha-512=10"})
				assert.Empty(t, asb.signatureAlgorithm)
				assert.Empty(t, asb.keyID)
				// not set by any of the options
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.identifiers)
			},
		},
		{
			uc: "with all possible options",
			opts: []SignatureNegotiationOption{
				WithRequestedLabel("foo"),
				WithRequestedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
				WithRequestedSignatureAlgorithm(RsaPssSha512),
				WithRequestedKeyID("bar"),
				WithRequestedContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 2}),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, asb)
				require.NotNil(t, asb.nonceGetter)
				nonce, err := asb.nonceGetter.GetNonce(context.TODO())
				require.NoError(t, err)
				require.Equal(t, "abc", nonce)
				assert.Equal(t, "foo", asb.label)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{"sha-512=2"})
				assert.Equal(t, RsaPssSha512, asb.signatureAlgorithm)
				assert.Equal(t, "bar", asb.keyID)
				// not set by any of the options
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.identifiers)
			},
		},
		{
			uc: "with error while applying the option",
			opts: []SignatureNegotiationOption{
				WithRequestedContentDigestAlgorithmPreferences(AlgorithmPreference{}),
			},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			v := &verifier{}
			exp := &expectations{}

			err := WithSignatureNegotiation(tc.opts...)(v, exp, false)

			tc.assert(t, err, exp.asb)
		})
	}
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
			uc:       "with component identifiers configuration error",
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
			uc:       "cannot verify and negotiate any possible signature",
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
			uc:       "with global defaults without signature negotiation",
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
				assert.Nil(t, exp.asb)
			},
		},
		{
			uc:       "with global defaults with signature negotiation",
			resolver: &KeyResolverMock{},
			opts: []VerifierOption{
				WithRequiredTag("test"),
				WithValidityTolerance(1 * time.Second),
				WithRequiredComponents("@status", "content-digest"),
				WithSignatureNegotiation(
					WithRequestedSignatureAlgorithm(RsaPssSha512),
					WithRequestedKeyID("bar"),
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
				assert.Len(t, exp.identifiers, 2)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Equal(t, "content-digest", exp.identifiers[1].Value)
				assert.Equal(t, 1*time.Second, exp.tolerance)
				require.NotNil(t, exp.asb)
				assert.IsType(t, nonceGetter{}, exp.asb.nonceGetter)
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
		assert            func(t *testing.T, err error, results VerificationResult)
	}{
		{
			uc:                "without signature-input header",
			opts:              []VerifierOption{WithValidateAllSignatures()},
			msg:               &Message{Header: make(http.Header)},
			configureResolver: func(t *testing.T, _ *KeyResolverMock) { t.Helper() },
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
			assert: func(t *testing.T, err error, results VerificationResult) {
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

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig" &&
							si.Message != nil &&
							len(si.Components) == 0 &&
							si.Parameters["expires"] == int64(1618884470) &&
							si.Parameters["keyid"] == "test" &&
							si.Parameters["tag"] == "foo"
					})).
					Return(KeyInfo{}, nil)
			},
			assert: func(t *testing.T, err error, _ VerificationResult) {
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
		{
			uc: "signature parameters negotiation for not present tagged signature",
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithRequiredComponents("@method", "content-digest"),
					WithSignatureNegotiation(
						WithRequestedSignatureAlgorithm(RsaPssSha512),
						WithRequestedKeyID("test-key"),
						WithRequestedLabel("bar"),
						WithRequestedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
						WithRequestedContentDigestAlgorithmPreferences(AlgorithmPreference{Sha256, 1}),
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
		{
			uc: "signature parameters negotiation for present signature with missing expires parameters",
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithSignatureNegotiation(
						WithRequestedSignatureAlgorithm(RsaPssSha512),
						WithRequestedKeyID("test-key"),
						WithRequestedLabel("bar"),
						WithRequestedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
						WithRequestedContentDigestAlgorithmPreferences(AlgorithmPreference{Sha256, 1}),
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
			configureResolver: func(t *testing.T, kr *KeyResolverMock) {
				t.Helper()

				kr.EXPECT().ResolveKey(mock.Anything,
					mock.MatchedBy(func(si SignatureInfo) bool {
						return si.Label == "sig" &&
							si.Message != nil &&
							si.Message.Header.Get("Content-Length") == "18" &&
							len(si.Components) == 0 &&
							si.Parameters["created"] == int64(1618884473) &&
							si.Parameters["keyid"] == "test-key" &&
							si.Parameters["nonce"] == "abc" &&
							si.Parameters["tag"] == "foo"
					})).
					Return(
						KeyInfo{
							Key: Key{Material: tkRSAPSS, Algorithm: RsaPssSha512},
						},
						nil,
					)
			},
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
		{
			uc: "signature parameters negotiation fails because of nonce error",
			opts: []VerifierOption{
				WithRequiredTag("foo",
					WithRequiredComponents("@method"),
					WithSignatureNegotiation(
						WithRequestedSignatureAlgorithm(RsaPssSha512),
						WithRequestedKeyID("test-key"),
						WithRequestedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", errors.New("test error") })),
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
		{
			uc: "signature verification fails due to invalid second content digest",
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
							Key: Key{Material: tkRSAPSS, Algorithm: RsaPssSha512},
						},
						nil,
					)
			},
			assert: func(t *testing.T, err error, _ VerificationResult) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorIs(t, err, ErrContentDigestMismatch)
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
		{
			uc: "invalid untagged signature is ignored",
			opts: []VerifierOption{
				WithRequiredTag("foo"),
				WithExpiredTimestampRequired(false),
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

				assert.Len(t, sig.Components, 0)

				assert.Len(t, sig.Parameters, 3)
				assert.Equal(t, int64(1618884473), sig.Parameters["created"])
				assert.Equal(t, "test-shared-secret", sig.Parameters["keyid"])
				assert.Equal(t, "foo", sig.Parameters["tag"])

				assert.Equal(t, map[string]string{"foo": "bar"}, sig.Metadata)
			},
		},
		{
			uc: "invalid untagged signature fails when validating all",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithExpiredTimestampRequired(false),
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
		{
			uc: "multiple valid signatures with different keys and metadata",
			opts: []VerifierOption{
				WithValidateAllSignatures(),
				WithExpiredTimestampRequired(false),
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
	} {
		t.Run(tc.uc, func(t *testing.T) {
			kr := NewKeyResolverMock(t)
			tc.configureResolver(t, kr)

			v, err := NewVerifier(kr, tc.opts...)
			require.NoError(t, err)

			results, err := v.Verify(tc.msg)
			tc.assert(t, err, results)
		})
	}
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
				tagExpectations: map[string]*expectations{"foo": {}},
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
				tagExpectations: map[string]*expectations{"foo": {}},
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
				tagExpectations: map[string]*expectations{"foo": {}},
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
				tagExpectations: map[string]*expectations{"foo": {}},
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
