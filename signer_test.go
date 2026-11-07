package httpsig

import (
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

	for uc, tc := range map[string]struct {
		key any
		alg SignatureAlgorithm
		typ any
		err error
	}{
		"unsupported key type": {key: "foo", err: ErrUnsupportedKeyType},
		"ed25519 signer":       {key: ek25519, alg: Ed25519, typ: &ed25519Signer{}},
		"rsa signer":           {key: pk2048, alg: RsaPssSha256, typ: &rsaSigner{}},
		"ecdsa signer":         {key: pkp256, alg: EcdsaP256Sha256, typ: &ecdsaSigner{}},
		"hmac signer":          {key: k256, alg: HmacSha256, typ: &symmetricSigner{}},
		"message signer":       {key: &MessageSignerMock{}, alg: SignatureAlgorithm("custom-alg"), typ: &messageSignerAdaptor{}},
	} {
		t.Run(uc, func(t *testing.T) {
			sig, err := newPayloadSigner(tc.key, tc.alg)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, sig)
			} else {
				require.NoError(t, err)
				require.NotNil(t, sig)
				require.IsType(t, tc.typ, sig)
			}
		})
	}
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
			key:  Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{WithComponents(`"@test"`)},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		{
			uc:   "alg parameter requires a registered algorithm",
			key:  Key{Algorithm: HmacSha384, Material: []byte("secret")},
			opts: []SignerOption{WithAlg()},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()

				require.ErrorIs(t, err, ErrUnsupportedAlgorithm)
			},
		},
		{
			uc:   "unknown algorithm with message signer",
			key:  Key{Algorithm: SignatureAlgorithm("custom-alg"), Material: &MessageSignerMock{}},
			opts: []SignerOption{WithAlg()},
			assert: func(t *testing.T, err error, s Signer) {
				t.Helper()

				require.NoError(t, err)
				assert.NotNil(t, s)
			},
		},
		{
			uc:   "reserved signature parameter",
			key:  Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{WithParameter("created", int64(1))},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:   "static nonce parameter is not allowed",
			key:  Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{WithParameter("nonce", "fixed-nonce")},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:   "invalid signature parameter name",
			key:  Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{WithParameter("Invalid Name", "value")},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:   "invalid signature parameter value",
			key:  Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{WithParameter("example", struct{}{})},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "duplicate signature parameter",
			key: Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{
				WithParameter("example", "a"),
				WithParameter("example", "b"),
			},
			assert: func(t *testing.T, err error, _ Signer) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "successful without configuration",
			key: Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			assert: func(t *testing.T, err error, sgnr Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sgnr)

				s := sgnr.(*signer)

				assert.Equal(t, "sig", s.label)
				assert.Equal(t, 30*time.Second, s.ttl)
				assert.IsType(t, &ecdsaSigner{}, s.ps)
				assert.Empty(t, s.tag)
				assert.Empty(t, s.ids)
			},
		},
		{
			uc:  "successful with configuration",
			key: Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{
				WithComponents(`"@status"`),
				WithTag("foo"),
				WithTTL(1 * time.Second),
				WithLabel("bar"),
				WithKeyID("test"),
			},
			assert: func(t *testing.T, err error, sgnr Signer) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, sgnr)

				s := sgnr.(*signer)

				assert.Equal(t, "bar", s.label)
				assert.Equal(t, 1*time.Second, s.ttl)
				assert.IsType(t, &ecdsaSigner{}, s.ps)
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
	pkp384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
		uc       string
		key      Key
		opts     []SignerOption
		signOpts []SignOption
		msg      *Message
		assert   func(t *testing.T, err error, header http.Header)
	}{
		{
			uc:   "signer omits nonce unless supplied per call",
			key:  Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{WithTTL(0)},
			msg:  &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created=1618884473`, header.Get("Signature-Input"))
			},
		},
		{
			uc:  "failed updating message (adding content-digest)",
			key: Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{
				WithComponents(`"content-digest"`),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Length": []string{"18"},
				},
				IsRequest: true,
				Body: func() (io.ReadCloser, error) {
					return nil, errors.New("test error")
				},
			},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:  "failed creating signature base",
			key: Key{Algorithm: EcdsaP384Sha384, Material: pkp384},
			opts: []SignerOption{
				WithComponents(`"@status"`),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
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
			uc:  "static extension parameters",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{
				WithTTL(0),
				WithParameter("example-token", Token("hello")),
				WithParameter("example-bytes", []byte("data")),
			},
			msg: &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created=1618884473;example-token=hello;example-bytes=:ZGF0YQ==:`, header.Get("Signature-Input"))
			},
		},
		{
			uc:  "per-call label overrides configured label",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{
				WithTTL(0),
				WithLabel("static"),
			},
			signOpts: []SignOption{WithLabel("dynamic")},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `dynamic=();created=1618884473`, header.Get("Signature-Input"))
			},
		},
		{
			uc:  "per-call nonce is included",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{
				WithTTL(0),
			},
			signOpts: []SignOption{WithParameter("nonce", "requested-nonce")},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created=1618884473;nonce="requested-nonce"`, header.Get("Signature-Input"))
			},
		},
		{
			uc:  "additional parameters for a single signature",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{
				WithTTL(0),
				WithParameter("static", Token("hello")),
			},
			signOpts: []SignOption{
				WithParameter("wimse-req-nonce", "request-nonce"),
				WithParameter("dynamic-flag", true),
			},
			msg: &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()
				require.NoError(t, err)
				assert.Equal(t, `sig=();created=1618884473;static=hello;wimse-req-nonce="request-nonce";dynamic-flag`, header.Get("Signature-Input"))
			},
		},
		{
			uc:       "reserved per-call parameter",
			key:      Key{Algorithm: HmacSha256, Material: []byte("secret")},
			signOpts: []SignOption{WithParameter("created", int64(1))},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:       "nonce parameter requires a string",
			key:      Key{Algorithm: HmacSha256, Material: []byte("secret")},
			signOpts: []SignOption{WithParameter("nonce", Token("not-a-string"))},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:       "nonce parameter cannot be empty",
			key:      Key{Algorithm: HmacSha256, Material: []byte("secret")},
			signOpts: []SignOption{WithParameter("nonce", "")},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "duplicate per-call nonce",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			signOpts: []SignOption{
				WithParameter("nonce", "one"),
				WithParameter("nonce", "two"),
			},
			msg: &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "duplicate per-call parameter",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			signOpts: []SignOption{
				WithParameter("example", "a"),
				WithParameter("example", "b"),
			},
			msg: &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "static and per-call parameter collision",
			key: Key{Algorithm: HmacSha256, Material: []byte("secret")},
			opts: []SignerOption{
				WithParameter("example", "static"),
			},
			signOpts: []SignOption{WithParameter("example", "dynamic")},
			msg:      &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ http.Header) {
				t.Helper()
				require.ErrorIs(t, err, ErrParameter)
			},
		},
		{
			uc:  "include alg parameter when requested",
			key: Key{Algorithm: HmacSha256, Material: tkMAC},
			opts: []SignerOption{
				WithAlg(),
				WithTTL(0),
			},
			msg: &Message{Header: http.Header{}, IsRequest: true},
			assert: func(t *testing.T, err error, header http.Header) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, `sig=();created=1618884473;alg="hmac-sha256"`, header.Get("Signature-Input"))
			},
		},
		{
			// https://www.rfc-editor.org/rfc/rfc9421.html#name-minimal-signature-using-rsa
			uc:  "B.2.1. minimal signature using rsa-pss-sha512",
			key: Key{Algorithm: RsaPssSha512, Material: tkRSAPSS},
			opts: []SignerOption{
				WithLabel("sig-b21"),
				WithTTL(0),
				WithKeyID("test-key-rsa-pss"),
			},
			signOpts: []SignOption{WithParameter("nonce", "b3k2pp5k7z-50gnwp.yemd")},
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
			key: Key{Algorithm: RsaPssSha512, Material: tkRSAPSS},
			opts: []SignerOption{
				WithLabel("sig-b22"),
				WithTTL(0),
				WithComponents(`"@authority"`, `"content-digest"`, `"@query-param";name="Pet"`),
				WithTag("header-example"),
				WithContentDigestAlgorithm(Sha512),
				WithKeyID("test-key-rsa-pss"),
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
			key: Key{Algorithm: RsaPssSha512, Material: tkRSAPSS},
			opts: []SignerOption{
				WithLabel("sig-b23"),
				WithTTL(0),
				WithComponents(
					`"date"`, `"@method"`, `"@path"`, `"@query"`, `"@authority"`, `"content-type"`, `"content-digest"`, `"content-length"`,
				),
				WithContentDigestAlgorithm(Sha512),
				WithKeyID("test-key-rsa-pss"),
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
			key: Key{Algorithm: EcdsaP256Sha256, Material: tkECCP256},
			opts: []SignerOption{
				WithLabel("sig-b24"),
				WithTTL(0),
				WithComponents(`"@status"`, `"content-type"`, `"content-digest"`, `"content-length"`),
				WithContentDigestAlgorithm(Sha512),
				WithKeyID("test-key-ecc-p256"),
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
			key: Key{Algorithm: HmacSha256, Material: tkMAC},
			opts: []SignerOption{
				WithLabel("sig-b25"),
				WithTTL(0),
				WithComponents(`"date"`, `"@authority"`, `"content-type"`),
				WithKeyID("test-shared-secret"),
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
			key: Key{Algorithm: Ed25519, Material: tkEd25519},
			opts: []SignerOption{
				WithLabel("sig-b26"),
				WithTTL(0),
				WithComponents(`"date"`, `"@method"`, `"@path"`, `"@authority"`, `"content-type"`, `"content-length"`),
				WithKeyID("test-key-ed25519"),
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
		{
			uc:  "overwrites stale content-digest when signing content-digest component",
			key: Key{Algorithm: RsaPssSha512, Material: tkRSAPSS},
			opts: []SignerOption{
				WithLabel("sig-content-digest"),
				WithTTL(0),
				WithComponents(`"content-digest"`),
				WithContentDigestAlgorithm(Sha256),
				WithKeyID("test-key-rsa-pss"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-256=:stale:"},
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

				assert.Equal(
					t,
					"sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
					header.Get("Content-Digest"),
				)

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-content-digest=("content-digest");created=1618884473;keyid="test-key-rsa-pss"`, sigInput)

				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-content-digest=:"))
			},
		},
		{
			uc:  "preserves existing content-digest when content-digest component is not signed",
			key: Key{Algorithm: RsaPssSha512, Material: tkRSAPSS},
			opts: []SignerOption{
				WithLabel("sig-no-content-digest"),
				WithTTL(0),
				WithComponents(`"date"`, `"@method"`),
				WithContentDigestAlgorithm(Sha256),
				WithKeyID("test-key-rsa-pss"),
			},
			msg: &Message{
				Method:    http.MethodPost,
				Authority: "example.com",
				URL:       testURL,
				Header: http.Header{
					"Host":           []string{"example.com"},
					"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
					"Content-Type":   []string{"application/json"},
					"Content-Digest": []string{"sha-256=:stale:"},
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

				assert.Equal(t, "sha-256=:stale:", header.Get("Content-Digest"))

				sigInput := header.Get("Signature-Input")
				assert.Equal(t, `sig-no-content-digest=("date" "@method");created=1618884473;keyid="test-key-rsa-pss"`, sigInput)

				sig := header.Get("Signature")
				assert.True(t, strings.HasPrefix(sig, "sig-no-content-digest=:"))
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			withRFC9421Time(t, func(t *testing.T) {
				t.Helper()

				s, err := NewSigner(tc.key, tc.opts...)
				require.NoError(t, err)

				res, err := s.Sign(tc.msg, tc.signOpts...)

				tc.assert(t, err, res)
			})
		})
	}

	t.Run("per-call label does not persist", func(t *testing.T) {
		withRFC9421Time(t, func(t *testing.T) {
			t.Helper()

			s, err := NewSigner(Key{Algorithm: HmacSha256, Material: []byte("secret")},
				WithTTL(0),
				WithLabel("static"),
			)
			require.NoError(t, err)

			first, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true}, WithLabel("dynamic"))
			require.NoError(t, err)
			assert.Equal(t, `dynamic=();created=1618884473`, first.Get("Signature-Input"))

			second, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true})
			require.NoError(t, err)
			assert.Equal(t, `static=();created=1618884473`, second.Get("Signature-Input"))
		})
	})

	t.Run("per-call nonce does not persist", func(t *testing.T) {
		withRFC9421Time(t, func(t *testing.T) {
			t.Helper()

			s, err := NewSigner(Key{Algorithm: HmacSha256, Material: []byte("secret")}, WithTTL(0))
			require.NoError(t, err)

			first, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true},
				WithParameter("nonce", "requested-nonce"))
			require.NoError(t, err)
			assert.Equal(t, `sig=();created=1618884473;nonce="requested-nonce"`, first.Get("Signature-Input"))

			second, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true})
			require.NoError(t, err)
			assert.Equal(t, `sig=();created=1618884473`, second.Get("Signature-Input"))
		})
	})

	t.Run("per-call parameters do not persist", func(t *testing.T) {
		withRFC9421Time(t, func(t *testing.T) {
			t.Helper()

			s, err := NewSigner(Key{Algorithm: HmacSha256, Material: []byte("secret")},
				WithTTL(0),
			)
			require.NoError(t, err)

			first, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true},
				WithParameter("wimse-req-nonce", "request-nonce"))
			require.NoError(t, err)
			assert.Contains(t, first.Get("Signature-Input"), `;wimse-req-nonce="request-nonce"`)

			second, err := s.Sign(&Message{Header: http.Header{}, IsRequest: true})
			require.NoError(t, err)
			assert.Equal(t, `sig=();created=1618884473`, second.Get("Signature-Input"))
		})
	})
}
