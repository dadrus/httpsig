package httpsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignatureParametersKeyID(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   string
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{KeyID: "test-key"},
			want:   "test-key",
			wantOK: true,
		},
		"empty string": {
			params: SignatureParameters{KeyID: ""},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{KeyID: int64(1234)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.KeyID()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersAlg(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   string
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{Alg: "ed25519"},
			want:   "ed25519",
			wantOK: true,
		},
		"empty string": {
			params: SignatureParameters{Alg: ""},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{Alg: int64(1234)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.Alg()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersCreated(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   int64
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{Created: int64(1234)},
			want:   1234,
			wantOK: true,
		},
		"zero value": {
			params: SignatureParameters{Created: int64(0)},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{Created: "1234"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.Created()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersExpires(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   int64
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{Expires: int64(5678)},
			want:   5678,
			wantOK: true,
		},
		"zero value": {
			params: SignatureParameters{Expires: int64(0)},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{Expires: "5678"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.Expires()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersNonce(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   string
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{Nonce: "request-nonce"},
			want:   "request-nonce",
			wantOK: true,
		},
		"empty string": {
			params: SignatureParameters{Nonce: ""},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{Nonce: int64(1234)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.Nonce()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersTag(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		params SignatureParameters
		want   string
		wantOK bool
	}{
		"present": {
			params: SignatureParameters{Tag: "profile"},
			want:   "profile",
			wantOK: true,
		},
		"empty string": {
			params: SignatureParameters{Tag: ""},
			wantOK: true,
		},
		"missing": {
			params: SignatureParameters{},
		},
		"nil map": {},
		"wrong type": {
			params: SignatureParameters{Tag: int64(1234)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := tc.params.Tag()

			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantOK, ok)
		})
	}
}

func TestSignatureParametersExtension(t *testing.T) {
	t.Parallel()

	name := SignatureParameter("wimse-aud")
	params := SignatureParameters{name: "service-a"}

	assert.Equal(t, "service-a", params[name])
	assert.Equal(t, "service-a", params["wimse-aud"])
}
