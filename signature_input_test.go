package httpsig

import (
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureInput(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifiers []*componentIdentifier
		params      *httpsfv.Params
		assert      func(t *testing.T, input *signatureInput)
	}{
		"without parameters or identifiers": {
			assert: func(t *testing.T, input *signatureInput) {
				t.Helper()

				require.NotNil(t, input)
				require.NotNil(t, input.value.Params)
				assert.Empty(t, input.value.Params.Names())
				assert.Empty(t, input.value.Items)
				assert.Empty(t, input.identifiers)
			},
		},
		"with parameters only": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(1577836800))
				params.Add("wimse-aud", "https://api.example.com")

				return params
			}(),
			assert: func(t *testing.T, input *signatureInput) {
				t.Helper()

				require.NotNil(t, input)
				assert.Equal(t, []string{string(Created), "wimse-aud"}, input.value.Params.Names())
				assert.Empty(t, input.value.Items)
				assert.Empty(t, input.identifiers)
			},
		},
		"with identifiers and parameters": {
			identifiers: []*componentIdentifier{
				{Item: httpsfv.Item{Value: "@method", Params: httpsfv.NewParams()}},
				{Item: httpsfv.Item{Value: "user-agent", Params: httpsfv.NewParams()}},
			},
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Tag), "web-bot-auth")

				return params
			}(),
			assert: func(t *testing.T, input *signatureInput) {
				t.Helper()

				require.NotNil(t, input)
				assert.Equal(t, []string{string(Tag)}, input.value.Params.Names())
				require.Len(t, input.identifiers, 2)
				assert.Equal(t, "@method", input.identifiers[0].Value)
				assert.Equal(t, "user-agent", input.identifiers[1].Value)
				require.Len(t, input.value.Items, 2)
				assert.Equal(t, "@method", input.value.Items[0].Value)
				assert.Equal(t, "user-agent", input.value.Items[1].Value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := newSignatureInput(tc.identifiers, tc.params)

			tc.assert(t, input)
		})
	}
}

func TestParseSignatureInput(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		list   httpsfv.InnerList
		assert func(t *testing.T, err error, input *signatureInput)
	}{
		"empty list": {
			assert: func(t *testing.T, err error, input *signatureInput) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, input)
				assert.Empty(t, input.value.Items)
				assert.Nil(t, input.value.Params)
				assert.Empty(t, input.identifiers)
			},
		},
		"invalid component identifier": {
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{{Value: "@unsupported", Params: httpsfv.NewParams()}},
			},
			assert: func(t *testing.T, err error, input *signatureInput) {
				t.Helper()

				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				assert.Nil(t, input)
			},
		},
		"invalid signature parameter": {
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{{Value: "@method", Params: httpsfv.NewParams()}},
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), "not-an-integer")

					return params
				}(),
			},
			assert: func(t *testing.T, err error, input *signatureInput) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Created))
				assert.Nil(t, input)
			},
		},
		"valid list with standard and unknown parameters": {
			list: httpsfv.InnerList{
				Items: []httpsfv.Item{
					{Value: "@method", Params: httpsfv.NewParams()},
					{Value: "user-agent", Params: httpsfv.NewParams()},
				},
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), int64(1577836800))
					params.Add(string(Tag), "wimse-workload-to-workload")
					params.Add("wimse-sign-response", true)

					return params
				}(),
			},
			assert: func(t *testing.T, err error, input *signatureInput) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, input)
				assert.Equal(t, []string{
					string(Created), string(Tag), "wimse-sign-response",
				}, input.value.Params.Names())

				value, present := input.value.Params.Get("wimse-sign-response")
				require.True(t, present)
				assert.Equal(t, true, value)
				require.Len(t, input.identifiers, 2)
				assert.Equal(t, "@method", input.identifiers[0].Value)
				assert.Equal(t, "user-agent", input.identifiers[1].Value)
				require.Len(t, input.value.Items, 2)
				assert.Equal(t, "@method", input.value.Items[0].Value)
				assert.Equal(t, "user-agent", input.value.Items[1].Value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input, err := parseSignatureInput(tc.list)

			tc.assert(t, err, input)
		})
	}
}

func TestValidateSignatureInputParameters(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params *httpsfv.Params
		assert func(t *testing.T, err error)
	}{
		"nil parameters": {
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"empty parameters": {
			params: httpsfv.NewParams(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"valid timestamp parameters": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(0))
				params.Add(string(Expires), int64(1577836800))

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"invalid created parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), "0")

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Created))
			},
		},
		"invalid expires parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Expires), "0")

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Expires))
			},
		},
		"valid string parameters": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(KeyID), "")
				params.Add(string(Alg), string(RsaPssSha384))
				params.Add(string(Nonce), "n-123")
				params.Add(string(Tag), "")

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"invalid keyid parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(KeyID), int64(1))

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(KeyID))
			},
		},
		"invalid alg parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Alg), int64(1))

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Alg))
			},
		},
		"invalid nonce parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Nonce), int64(1))

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Nonce))
			},
		},
		"invalid tag parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Tag), int64(1))

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedSignatureParameter)
				require.ErrorContains(t, err, string(Tag))
			},
		},
		"unknown parameters are allowed": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add("wimse-aud", "https://api.example.com")
				params.Add("wimse-sign-response", true)

				return params
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			err := validateSignatureInputParameters(tc.params)

			tc.assert(t, err)
		})
	}
}

func TestSignatureInputParameter(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params *httpsfv.Params
		name   SignatureParameter
		assert func(t *testing.T, value any, present bool)
	}{
		"nil parameters": {
			name: KeyID,
			assert: func(t *testing.T, value any, present bool) {
				t.Helper()

				assert.False(t, present)
				assert.Nil(t, value)
			},
		},
		"missing parameter": {
			params: httpsfv.NewParams(),
			name:   Created,
			assert: func(t *testing.T, value any, present bool) {
				t.Helper()

				assert.False(t, present)
				assert.Nil(t, value)
			},
		},
		"present parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(1577836800))

				return params
			}(),
			name: Created,
			assert: func(t *testing.T, value any, present bool) {
				t.Helper()

				require.True(t, present)
				assert.Equal(t, int64(1577836800), value)
			},
		},
		"present zero value": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(0))

				return params
			}(),
			name: Created,
			assert: func(t *testing.T, value any, present bool) {
				t.Helper()

				require.True(t, present)
				assert.Equal(t, int64(0), value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.parameter(tc.name)

			tc.assert(t, value, present)
		})
	}
}

func TestSignatureInputStringParameter(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		name     SignatureParameter
		expected string
	}{
		"missing parameter": {
			name: KeyID,
		},
		"present parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Nonce), "nonce-123")

				return params
			}(),
			name:     Nonce,
			expected: "nonce-123",
		},
		"present empty parameter": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(KeyID), "")

				return params
			}(),
			name: KeyID,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.stringParameter(tc.name)

			if tc.params == nil {
				require.False(t, present)
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputTimestamp(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		name     SignatureParameter
		expected time.Time
	}{
		"missing": {
			name: Created,
		},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(1577836800))

				return params
			}(),
			name:     Created,
			expected: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		"present zero timestamp": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Expires), int64(0))

				return params
			}(),
			name:     Expires,
			expected: time.Unix(0, 0).UTC(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.timestamp(tc.name)

			if tc.params == nil {
				require.False(t, present)
				assert.True(t, value.IsZero())
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputCreated(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected time.Time
	}{
		"missing": {},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(1577836800))

				return params
			}(),
			expected: time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		"present zero created": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Created), int64(0))

				return params
			}(),
			expected: time.Unix(0, 0).UTC(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.created()

			if tc.params == nil {
				require.False(t, present)
				assert.True(t, value.IsZero())
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputExpires(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected time.Time
	}{
		"missing": {},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Expires), int64(1609459200))

				return params
			}(),
			expected: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		"present zero expires": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Expires), int64(0))

				return params
			}(),
			expected: time.Unix(0, 0).UTC(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.expires()

			if tc.params == nil {
				require.False(t, present)
				assert.True(t, value.IsZero())
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputNonce(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected string
	}{
		"missing": {},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Nonce), "nonce-123")

				return params
			}(),
			expected: "nonce-123",
		},
		"present but empty": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Nonce), "")

				return params
			}(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.nonce()

			if tc.params == nil {
				require.False(t, present)
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputKeyID(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected string
	}{
		"missing": {},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(KeyID), "key-123")

				return params
			}(),
			expected: "key-123",
		},
		"present but empty": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(KeyID), "")

				return params
			}(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.keyID()

			if tc.params == nil {
				require.False(t, present)
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputAlgorithm(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected SignatureAlgorithm
	}{
		"missing": {},
		"present": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Alg), string(RsaPssSha384))

				return params
			}(),
			expected: RsaPssSha384,
		},
		"present but empty": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Alg), "")

				return params
			}(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.algorithm()

			if tc.params == nil {
				require.False(t, present)
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputTag(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params   *httpsfv.Params
		expected string
	}{
		"missing tag": {},
		"present tag": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Tag), "web-bot-auth")
				return params
			}(),
			expected: "web-bot-auth",
		},
		"present empty tag": {
			params: func() *httpsfv.Params {
				params := httpsfv.NewParams()
				params.Add(string(Tag), "")

				return params
			}(),
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{value: httpsfv.InnerList{Params: tc.params}}

			value, present := input.tag()

			if tc.params == nil {
				require.False(t, present)
			} else {
				require.True(t, present)
				assert.Equal(t, tc.expected, value)
			}
		})
	}
}

func TestSignatureInputHasIdentifier(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		given      []*componentIdentifier
		identifier *componentIdentifier
		expected   bool
	}{
		"no identifiers": {
			identifier: &componentIdentifier{
				Item: httpsfv.Item{Value: "@method", Params: httpsfv.NewParams()},
			},
			expected: false,
		},
		"matching identifier": {
			given: []*componentIdentifier{{
				Item: httpsfv.Item{Value: "@method", Params: httpsfv.NewParams()},
			}},
			identifier: &componentIdentifier{
				Item: httpsfv.Item{Value: "@method", Params: httpsfv.NewParams()},
			},
			expected: true,
		},
		"different identifier name": {
			given: []*componentIdentifier{{
				Item: httpsfv.Item{Value: "@method", Params: httpsfv.NewParams()},
			}},
			identifier: &componentIdentifier{
				Item: httpsfv.Item{Value: "@authority", Params: httpsfv.NewParams()},
			},
			expected: false,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			input := &signatureInput{identifiers: tc.given}

			found := input.hasIdentifier(tc.identifier)

			require.Equal(t, tc.expected, found)
		})
	}
}
