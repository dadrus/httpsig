package httpsig

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithExpectedKey(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc        string
		key       Key
		expKeyID  string
		expKeyAlg SignatureAlgorithm
	}{
		{uc: "no actual data provided"},
		{uc: "only KeyID provided", key: Key{KeyID: "test"}, expKeyID: "test"},
		{uc: "only KeyAlg provided", key: Key{Algorithm: RsaPssSha512}, expKeyAlg: RsaPssSha512},
		{uc: "KeyID and KeyAlg provided", key: Key{KeyID: "foo", Algorithm: EcdsaP256Sha256}, expKeyID: "foo", expKeyAlg: EcdsaP256Sha256},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithExpectedKey(tc.key)(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.expKeyID, asb.keyID)
			assert.Equal(t, tc.expKeyAlg, asb.keyAlgorithm)
		})
	}
}

func TestWithExpectedNonce(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc  string
		ng  NonceGetter
		exp NonceGetter
	}{
		{uc: "nil NonceGetter", exp: nonceGetter{}},
		{uc: "custom NonceGetter", ng: &NonceGetterMock{}, exp: &NonceGetterMock{}},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{nonceGetter: nonceGetter{}}

			err := WithExpectedNonce(tc.ng)(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.exp, asb.nonceGetter)
		})
	}
}

func TestWithExpectedLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc    string
		label string
		exp   string
	}{
		{uc: "empty label", exp: "foo"},
		{uc: "custom label", label: "bar", exp: "bar"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{label: "foo"}

			err := WithExpectedLabel(tc.label)(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.exp, asb.label)
		})
	}
}

func TestWithExpectedComponents(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc          string
		identifiers []string
		assert      func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		{
			uc: "no identifiers provided",
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.identifiers)
			},
		},
		{
			uc:          "invalid identifiers provided",
			identifiers: []string{"@foo"},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		{
			uc:          "valid identifiers without content-digest",
			identifiers: []string{"@status", "x-foo-bar"},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Len(t, asb.identifiers, 2)
				assert.Equal(t, "@status", asb.identifiers[0].Value)
				assert.Equal(t, "x-foo-bar", asb.identifiers[1].Value)
			},
		},
		{
			uc:          "valid identifiers with content-digest",
			identifiers: []string{"@status", "content-digest", "x-foo-bar"},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, asb.wantContentDigest)
				assert.Len(t, asb.identifiers, 3)
				assert.Equal(t, "@status", asb.identifiers[0].Value)
				assert.Equal(t, "content-digest", asb.identifiers[1].Value)
				assert.Equal(t, "x-foo-bar", asb.identifiers[2].Value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{label: "foo"}

			err := WithExpectedComponents(tc.identifiers...)(asb)

			tc.assert(t, err, asb)
		})
	}
}

func TestWithContentDigestAlgorithmPreferences(t *testing.T) {
	t.Parallel()

	defaultPreference := AlgorithmPreference{Algorithm: Sha256, Preference: 2}.String()

	for _, tc := range []struct {
		uc       string
		prefs    []AlgorithmPreference
		expErr   error
		expPrefs []string
	}{
		{
			uc:       "no preferences provided",
			expPrefs: []string{defaultPreference},
		},
		{
			uc:       "no algorithm provided in a preference",
			prefs:    []AlgorithmPreference{{Sha256, 0}, {DigestAlgorithm(""), 0}},
			expErr:   ErrParameter,
			expPrefs: []string{defaultPreference},
		},
		{
			uc:    "valid options provided",
			prefs: []AlgorithmPreference{{Sha512, 0}, {Sha256, 1}},
			expPrefs: []string{
				AlgorithmPreference{Sha512, 0}.String(),
				AlgorithmPreference{Sha256, 1}.String(),
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{
				cdAlgPrefs: []string{defaultPreference},
			}

			err := WithContentDigestAlgorithmPreferences(tc.prefs...)(asb)

			if tc.expErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
				require.ElementsMatch(t, asb.cdAlgPrefs, tc.expPrefs)
			}
		})
	}
}

func TestWithExpectedTag(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc  string
		tag string
	}{
		{uc: "empty tag"},
		{uc: "custom tag", tag: "foo"},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithExpectedTag(tc.tag)(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.tag, asb.tag)
		})
	}
}

func TestWithExpectedCreatedTimestamp(t *testing.T) {
	t.Parallel()

	asb := &AcceptSignatureBuilder{addCreatedTS: true}

	err := WithExpectedCreatedTimestamp(false)(asb)

	require.NoError(t, err)
	assert.False(t, asb.addCreatedTS)
}

func TestWithExpectedExpiresTimestamp(t *testing.T) {
	t.Parallel()

	asb := &AcceptSignatureBuilder{addExpiresTS: true}

	err := WithExpectedExpiresTimestamp(false)(asb)

	require.NoError(t, err)
	assert.False(t, asb.addExpiresTS)
}

func TestNewAcceptedSignature(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opts   []AcceptSignatureOption
		assert func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		{
			uc: "no options provided",
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.identifiers)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.keyID)
				assert.Empty(t, asb.keyAlgorithm)
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.Equal(t, nonceGetter{}, asb.nonceGetter)
				assert.Equal(t, "sig", asb.label)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{
					AlgorithmPreference{Algorithm: Sha256, Preference: 5}.String(),
					AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(),
				})
			},
		},
		{
			uc: "all possible options provided",
			opts: []AcceptSignatureOption{
				WithExpectedKey(Key{KeyID: "test", Algorithm: EcdsaP256Sha256}),
				WithExpectedNonce(&NonceGetterMock{}),
				WithExpectedLabel("foo"),
				WithExpectedComponents("@status", "content-digest;req"),
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 10}),
				WithExpectedTag("bar"),
				WithExpectedCreatedTimestamp(false),
				WithExpectedExpiresTimestamp(false),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, asb.wantContentDigest)
				assert.Len(t, asb.identifiers, 2)
				assert.Equal(t, "@status", asb.identifiers[0].Value)
				assert.Equal(t, "content-digest", asb.identifiers[1].Value)
				assert.Equal(t, "bar", asb.tag)
				assert.Equal(t, "test", asb.keyID)
				assert.Equal(t, EcdsaP256Sha256, asb.keyAlgorithm)
				assert.False(t, asb.addCreatedTS)
				assert.False(t, asb.addExpiresTS)
				assert.Equal(t, &NonceGetterMock{}, asb.nonceGetter)
				assert.Equal(t, "foo", asb.label)
				assert.ElementsMatch(t, asb.cdAlgPrefs, []string{
					AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(),
				})
			},
		},
		{
			uc: "option raises error",
			opts: []AcceptSignatureOption{
				WithExpectedComponents("@foo"),
			},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.Nil(t, asb)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			builder, err := NewAcceptSignature(tc.opts...)

			tc.assert(t, err, builder)
		})
	}
}

func TestAcceptSignatureBuilderBuild(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc     string
		opts   []AcceptSignatureOption
		assert func(t *testing.T, err error, hdr http.Header)
	}{
		{
			uc: "failing getting the nonce",
			opts: []AcceptSignatureOption{
				WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) {
					return "", errors.New("test error")
				})),
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
				require.Contains(t, err.Error(), "test error")
			},
		},
		{
			uc: "Accept-Signature only is added",
			opts: []AcceptSignatureOption{
				WithExpectedKey(Key{KeyID: "test", Algorithm: EcdsaP256Sha256}),
				WithExpectedComponents("@status", "x-foo-bar;req", "@method"),
				WithExpectedLabel("foo"),
				WithExpectedTag("bar"),
				WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "x-foo-bar";req "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				assert.Empty(t, hdr.Values(headerWantContentDigest))
			},
		},
		{
			uc: "Accept-Signature and Want-Content-Digest headers are added with default algorithms",
			opts: []AcceptSignatureOption{
				WithExpectedKey(Key{KeyID: "test", Algorithm: EcdsaP256Sha256}),
				WithExpectedComponents("@status", "content-digest", "@method"),
				WithExpectedLabel("foo"),
				WithExpectedTag("bar"),
				WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "content-digest" "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				values = hdr.Values(headerWantContentDigest)
				require.Len(t, values, 2)
				assert.ElementsMatch(t, values, []string{"sha-256=5", "sha-512=10"})
			},
		},
		{
			uc: "Accept-Signature and Want-Content-Digest headers are added with supplied algorithms",
			opts: []AcceptSignatureOption{
				WithExpectedKey(Key{KeyID: "test", Algorithm: EcdsaP256Sha256}),
				WithExpectedComponents("@status", "content-digest", "@method"),
				WithExpectedLabel("foo"),
				WithExpectedTag("bar"),
				WithExpectedNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 1}),
			},
			assert: func(t *testing.T, err error, hdr http.Header) {
				t.Helper()

				require.NoError(t, err)

				values := hdr.Values(headerAcceptSignature)
				require.Len(t, values, 1)
				assert.Equal(t, `foo=("@status" "content-digest" "@method");created;expires;keyid="test";alg="ecdsa-p256-sha256";nonce="abc";tag="bar"`, values[0])

				values = hdr.Values(headerWantContentDigest)
				require.Len(t, values, 1)
				assert.ElementsMatch(t, values, []string{"sha-512=1"})
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			hdr := make(http.Header)

			builder, err := NewAcceptSignature(tc.opts...)
			require.NoError(t, err)

			err = builder.Build(context.TODO(), hdr)

			tc.assert(t, err, hdr)
		})
	}
}
