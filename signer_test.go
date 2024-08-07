package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPayloadSigner(t *testing.T) {
	t.Parallel()

	_, ek25519, err := ed25519.GenerateKey(rand.Reader)
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
		{uc: "ed25519 signer", key: ek25519, alg: Ed25519, typ: &ed25519Signer{}},
		{uc: "rsa signer", key: pk2048, alg: RsaPssSha256, typ: &rsaSigner{}},
		{uc: "ecdsa signer", key: pkp256, alg: EcdsaP256Sha256, typ: &ecdsaSigner{}},
		{uc: "hmac signer", key: k256, alg: HmacSha256, typ: &symmetricSigner{}},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sig, err := newPayloadSigner(tc.key, "test", tc.alg)

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

func TestWithLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc           string
		label        string
		shouldUpdate bool
	}{
		{uc: "empty label", label: "", shouldUpdate: false},
		{uc: "not empty label", label: "foo", shouldUpdate: true},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			s := &signer{label: "test"}

			err := WithLabel(tc.label)(s)
			require.NoError(t, err)

			if tc.shouldUpdate {
				require.Equal(t, tc.label, s.label)
			} else {
				require.Equal(t, "test", s.label)
			}
		})
	}
}

func TestWithTTL(t *testing.T) {
	t.Parallel()

	ttl := 1 * time.Second
	s := &signer{ttl: 30 * time.Second}

	err := WithTTL(ttl)(s)

	require.NoError(t, err)
	require.Equal(t, ttl, s.ttl)
}

func TestWithComponentsForSigner(t *testing.T) {
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
			s := &signer{}

			err := WithComponents(tc.identifiers...)(s)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Len(t, s.ids, len(tc.identifiers))

				for i, id := range s.ids {
					vals := strings.Split(tc.identifiers[i], ";")
					assert.Equal(t, vals[0], id.Value)
				}
			}
		})
	}
}

func TestWithTag(t *testing.T) {
	t.Parallel()

	s := &signer{}

	err := WithTag("test")(s)
	require.NoError(t, err)

	assert.Equal(t, "test", s.tag)
}

func TestWithNonceGetter(t *testing.T) {
	t.Parallel()

	s := &signer{}

	err := WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) {
		return "foo", nil
	}))(s)
	require.NoError(t, err)

	nonce, err := s.ng.GetNonce(context.TODO())
	require.NoError(t, err)

	assert.Equal(t, "foo", nonce)
}

func TestNewSigner(t *testing.T) {
	t.Parallel()

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		key    Key
		opts   []SignerOption
		assert func(t *testing.T, err error, s Signer)
	}{
		{
			uc: "error while payload signer creation",
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedKeyType)
			},
		},
		{
			uc:   "error while applying configuration options",
			key:  Key{KeyID: "test", Algorithm: EcdsaP384Sha384, Key: pkp384},
			opts: []SignerOption{WithComponents("@test")},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		{
			uc:  "successful without configuration",
			key: Key{KeyID: "test", Algorithm: EcdsaP384Sha384, Key: pkp384},
			assert: func(t *testing.T, err error, sgnr Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sgnr)

				s := sgnr.(*signer)

				assert.Equal(t, "sig", s.label)
				assert.Equal(t, 30*time.Second, s.ttl)
				assert.IsType(t, &ecdsaSigner{}, s.ps)
				assert.NotNil(t, s.ng)
				assert.Empty(t, s.tag)
				assert.Empty(t, s.ids)
			},
		},
		{
			uc:  "successful with configuration",
			key: Key{KeyID: "test", Algorithm: EcdsaP384Sha384, Key: pkp384},
			opts: []SignerOption{
				WithComponents("@status"),
				WithTag("foo"),
				WithTTL(1 * time.Second),
				WithLabel("bar"),
			},
			assert: func(t *testing.T, err error, sgnr Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sgnr)

				s := sgnr.(*signer)

				assert.Equal(t, "bar", s.label)
				assert.Equal(t, 1*time.Second, s.ttl)
				assert.IsType(t, &ecdsaSigner{}, s.ps)
				assert.NotNil(t, s.ng)
				assert.Equal(t, "foo", s.tag)
				assert.NotEmpty(t, s.ids)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			sgnr, err := NewSigner(tc.key, tc.opts...)

			tc.assert(t, err, sgnr)
		})
	}
}

func TestSignerSign(t *testing.T) {
	// used by RFC9421 in test vectors
	currentTime = func() time.Time { return time.Unix(1618884473, 0) }
	filterAlgorithm = func(_ SignatureAlgorithm) SignatureAlgorithm { return "" }

	t.Cleanup(func() {
		currentTime = time.Now
		filterAlgorithm = func(alg SignatureAlgorithm) SignatureAlgorithm { return alg }
	})

	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pk512, err := rsa.GenerateKey(rand.Reader, 512) //nolint:gosec
	require.NoError(t, err)

	blockPrivate, _ := pem.Decode([]byte(testPrivKeyRSAPSS))
	assert.NotNil(t, blockPrivate, "could not decode test private key pem")

	// taken from crypto/x509/pkcs8.go
	type pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
		// optional attributes omitted.
	}

	var privKey pkcs8
	if _, err = asn1.Unmarshal(blockPrivate.Bytes, &privKey); err != nil {
		assert.NoError(t, err, "could not decode test private key pem")
	}

	tkRSAPSS, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
	require.NoError(t, err, "could not decode test private key")

	testURL, err := url.Parse("http://example.com/foo?param=Value&Pet=dog")
	require.NoError(t, err)

	blockPrivate, _ = pem.Decode([]byte(testPrivKeyECCP256))
	require.NotNil(t, blockPrivate, "could not decode test private key")

	tkECCP256, err := x509.ParseECPrivateKey(blockPrivate.Bytes)
	require.NoError(t, err, "could not decode test private key")

	tkMAC, err := base64.StdEncoding.DecodeString(testSharedSecret)
	require.NoError(t, err, "could not decode test shared secret")

	blockPrivate, _ = pem.Decode([]byte(testPrivKeyEd25519))
	assert.NotNil(t, blockPrivate, "could not decode test private key")

	rawKey, err := x509.ParsePKCS8PrivateKey(blockPrivate.Bytes)
	require.NoError(t, err, "could not decode test private key")

	tkEd25519 := rawKey.(ed25519.PrivateKey)

	for _, tc := range []struct {
		uc     string
		key    Key
		opts   []SignerOption
		msg    *Message
		assert func(t *testing.T, err error, header http.Header)
	}{
		{
			uc:  "failed creating signature parameters",
			key: Key{KeyID: "test", Algorithm: EcdsaP384Sha384, Key: pkp384},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", errors.New("test error") })),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:  "failed creating signature base",
			key: Key{KeyID: "test", Algorithm: EcdsaP384Sha384, Key: pkp384},
			opts: []SignerOption{
				WithComponents("@status"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:  "failed signing payload",
			key: Key{KeyID: "test", Algorithm: RsaPkcs1v15Sha512, Key: pk512},
			opts: []SignerOption{
				WithComponents("@authority"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-minimal-signature-using-rsa
			uc:  "B.2.1. minimal signature using rsa-pss-sha512",
			key: Key{KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512, Key: tkRSAPSS},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "b3k2pp5k7z-50gnwp.yemd", nil })),
				WithLabel("sig-b21"),
				WithTTL(0),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`, sigInput)

				// RSA-PSS is non-deterministic. So can't use the signature value from the test vector
				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-b21=:"))
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-selective-covered-component
			uc:  "B.2.2. selective covered components using rsa-pss-sha512",
			key: Key{KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512, Key: tkRSAPSS},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
				WithLabel("sig-b22"),
				WithTTL(0),
				WithComponents("@authority", "content-digest", "@query-param;name=\"Pet\""),
				WithTag("header-example"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`, sigInput)

				// RSA-PSS is non-deterministic. So can't use the signature value from the test vector
				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-b22=:"))
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-full-coverage-using-rsa-pss
			uc:  "B.2.3. full coverage using rsa-pss-sha512",
			key: Key{KeyID: "test-key-rsa-pss", Algorithm: RsaPssSha512, Key: tkRSAPSS},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
				WithLabel("sig-b23"),
				WithTTL(0),
				WithComponents(
					"date", "@method", "@path", "@query", "@authority", "content-type", "content-digest", "content-length",
				),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"hello": "world"}`)), nil
				},
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`, sigInput)

				// RSA-PSS is non-deterministic. So can't use the signature value from the test vector
				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-b23=:"))
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-response-using-ec
			uc:  "B.2.4. signing a response using ecdsa-p256-sha256",
			key: Key{KeyID: "test-key-ecc-p256", Algorithm: EcdsaP256Sha256, Key: tkECCP256},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
				WithLabel("sig-b24"),
				WithTTL(0),
				WithComponents("@status", "content-type", "content-digest", "content-length"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
					"Content-Length": []string{"23"},
				},
				Body: func() (io.ReadCloser, error) {
					return io.NopCloser(strings.NewReader(`{"message": "good dog"}`)), nil
				},
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`, sigInput)

				// ECDSA is non-deterministic. So can't use the signature value from the test vector
				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-b24=:"))
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-hma
			uc:  "B.2.5. signing a request using hmac-sha256",
			key: Key{KeyID: "test-shared-secret", Algorithm: HmacSha256, Key: tkMAC},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
				WithLabel("sig-b25"),
				WithTTL(0),
				WithComponents("date", "@authority", "content-type"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`, sigInput)

				sig := header.Get("Signature")
				assert.Equal(t, "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:", sig)
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-signing-a-request-using-ed2
			uc:  "B.2.6. signing a request using ed25519",
			key: Key{KeyID: "test-key-ed25519", Algorithm: Ed25519, Key: tkEd25519},
			opts: []SignerOption{
				WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) { return "", nil })),
				WithLabel("sig-b26"),
				WithTTL(0),
				WithComponents("date", "@method", "@path", "@authority", "content-type", "content-length"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
			},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`, sigInput)

				sig := header.Get("Signature")
				assert.Equal(t, "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:", sig)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			s, err := NewSigner(tc.key, tc.opts...)
			require.NoError(t, err)

			res, err := s.Sign(tc.msg)

			tc.assert(t, err, res)
		})
	}
}
