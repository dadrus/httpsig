package httpsig

import (
	"context"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerificationPolicyClone(t *testing.T) {
	t.Parallel()

	original := &verificationPolicy{
		requiredParameters:  []SignatureParameter{Nonce},
		forbiddenParameters: []SignatureParameter{Alg},
		expectedParameters:  []parameterOption{{name: "audience", value: "service-a"}},
	}

	clone := original.clone()
	require.NotSame(t, original, clone)

	clone.requiredParameters[0] = "created"
	clone.forbiddenParameters[0] = "keyid"
	clone.expectedParameters[0] = parameterOption{name: "audience", value: "service-b"}

	assert.Equal(t, []SignatureParameter{Nonce}, original.requiredParameters)
	assert.Equal(t, []SignatureParameter{Alg}, original.forbiddenParameters)
	assert.Equal(t, []parameterOption{{name: "audience", value: "service-a"}}, original.expectedParameters)
}

func TestVerificationPolicyWithOptions(t *testing.T) {
	t.Parallel()

	required := true
	original := &verificationPolicy{reqCreatedTS: &required, reqExpiresTS: &required}

	unchanged, err := original.withOptions("profile", nil)
	require.NoError(t, err)
	assert.Same(t, original, unchanged)

	effective, err := original.withOptions("profile", []VerifyOption{WithRequiredParameters("nonce")})
	require.NoError(t, err)
	require.NotSame(t, original, effective)
	assert.Equal(t, []SignatureParameter{Nonce}, effective.requiredParameters)
	assert.Empty(t, original.requiredParameters)

	_, err = original.withOptions("profile", []VerifyOption{WithForbiddenParameters("tag")})
	require.ErrorIs(t, err, ErrParameter)
	assert.Empty(t, original.forbiddenParameters)
}

func TestVerificationPolicyInherit(t *testing.T) {
	t.Parallel()

	globalIDs, err := toComponentIdentifiers([]string{"@method", "content-digest"})
	require.NoError(t, err)

	required := true
	global := &verificationPolicy{
		tolerance:           2 * time.Second,
		maxAge:              30 * time.Second,
		identifiers:         globalIDs,
		reqCreatedTS:        &required,
		reqExpiresTS:        &required,
		asb:                 &AcceptSignatureBuilder{label: "sig"},
		requiredParameters:  []SignatureParameter{Nonce},
		forbiddenParameters: []SignatureParameter{Alg},
		expectedParameters:  []parameterOption{{name: "audience", value: "service-a"}},
	}

	t.Run("inherits global configuration", func(t *testing.T) {
		t.Parallel()

		local := &verificationPolicy{tolerance: -1, maxAge: -1}
		require.NoError(t, local.inherit(global, "profile"))

		assert.Equal(t, global.tolerance, local.tolerance)
		assert.Equal(t, global.maxAge, local.maxAge)
		assert.Equal(t, global.identifiers, local.identifiers)
		assert.Equal(t, global.reqCreatedTS, local.reqCreatedTS)
		assert.Equal(t, global.reqExpiresTS, local.reqExpiresTS)
		assert.Equal(t, global.requiredParameters, local.requiredParameters)
		assert.Equal(t, global.forbiddenParameters, local.forbiddenParameters)
		assert.Equal(t, global.expectedParameters, local.expectedParameters)

		require.NotSame(t, global.asb, local.asb)
		assert.Equal(t, "profile", local.asb.tag)
		assert.Empty(t, global.asb.tag)
		assert.True(t, local.asb.wantContentDigest)
		assert.True(t, local.asb.addCreatedTS)
		assert.True(t, local.asb.addExpiresTS)
	})

	t.Run("keeps local overrides", func(t *testing.T) {
		t.Parallel()

		created := false
		expires := false
		localIDs, err := toComponentIdentifiers([]string{"@status"})
		require.NoError(t, err)

		localBuilder := &AcceptSignatureBuilder{label: "custom"}
		local := &verificationPolicy{
			tolerance:    time.Second,
			maxAge:       5 * time.Second,
			identifiers:  localIDs,
			reqCreatedTS: &created,
			reqExpiresTS: &expires,
			asb:          localBuilder,
		}
		require.NoError(t, local.inherit(global, "profile"))

		assert.Equal(t, time.Second, local.tolerance)
		assert.Equal(t, 5*time.Second, local.maxAge)
		assert.Equal(t, localIDs, local.identifiers)
		assert.False(t, *local.reqCreatedTS)
		assert.False(t, *local.reqExpiresTS)
		assert.Same(t, localBuilder, local.asb)
		assert.Equal(t, "custom", local.asb.label)
		assert.False(t, local.asb.wantContentDigest)
		assert.False(t, local.asb.addCreatedTS)
		assert.False(t, local.asb.addExpiresTS)
	})

	for uc, local := range map[string]verificationPolicy{
		"local requirement conflicts with global prohibition": {
			requiredParameters: []SignatureParameter{Alg},
		},
		"local prohibition conflicts with global required parameter": {
			forbiddenParameters: []SignatureParameter{Nonce},
		},
		"local value conflicts with global expectation": {
			expectedParameters: []parameterOption{{name: "audience", value: "other"}},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			local.tolerance = -1
			local.maxAge = -1
			require.ErrorIs(t, local.inherit(global, "profile"), ErrParameter)
		})
	}
}

func TestVerificationPolicyAssertMetadata(t *testing.T) {
	now := time.Now().UTC()
	falseVal := false
	trueVal := true

	for uc, tc := range map[string]struct {
		params httpsfv.InnerList
		exp    verificationPolicy
		assert func(t *testing.T, err error)
	}{
		"signature expired, no tolerance specified": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{reqExpiresTS: &falseVal, reqCreatedTS: &falseVal},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "expired")
			},
		},
		"signature is still valid with specified tolerance": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{
				tolerance:    3 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"signature is valid if expires in the future": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Expires), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{
				tolerance:    2 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"signature not yet valid, no tolerance specified": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{reqCreatedTS: &falseVal, reqExpiresTS: &falseVal},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "not yet valid")
			},
		},
		"signature already valid with specified tolerance": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{
				tolerance:    3 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"signature is valid if created in the past": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{
				maxAge:       30 * time.Second,
				reqCreatedTS: &falseVal,
				reqExpiresTS: &falseVal,
			},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"signature too old": {
			params: httpsfv.InnerList{
				Params: func() *httpsfv.Params {
					params := httpsfv.NewParams()
					params.Add(string(Created), now.Add(-2*time.Second).Unix())

					return params
				}(),
			},
			exp: verificationPolicy{reqCreatedTS: &falseVal, reqExpiresTS: &falseVal},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrValidity)
				require.ErrorContains(t, err, "too old")
			},
		},
		"expected component identifier missing": {
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp: func() verificationPolicy {
				ids, err := toComponentIdentifiers([]string{"@method;req", "@authority"})
				require.NoError(t, err)

				return verificationPolicy{identifiers: ids, reqCreatedTS: &falseVal, reqExpiresTS: &falseVal}
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `"@method";req, "@authority"`)
			},
		},
		"expected created parameter is missing": {
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp:    verificationPolicy{reqCreatedTS: &trueVal, reqExpiresTS: &falseVal},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `created parameter`)
			},
		},
		"expected expires parameter is missing": {
			params: httpsfv.InnerList{Params: httpsfv.NewParams()},
			exp:    verificationPolicy{reqCreatedTS: &falseVal, reqExpiresTS: &trueVal},
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMissingParameter)
				require.ErrorContains(t, err, `expires parameter`)
			},
		},
		"successful assertion with all possible parameters": {
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
			exp: func() verificationPolicy {
				ids, err := toComponentIdentifiers([]string{"@authority", "@method"})
				require.NoError(t, err)

				return verificationPolicy{
					identifiers: ids,
					maxAge:      5 * time.Second,
				}
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			msg := &Message{Context: context.TODO()}

			si, err := parseSignatureInput(tc.params)
			require.NoError(t, err)

			err = tc.exp.assertMetadata(si, msg)

			tc.assert(t, err)
		})
	}
}

func TestVerificationPolicyAssertKeyAlgorithm(t *testing.T) {
	for uc, tc := range map[string]struct {
		parameterAlg SignatureAlgorithm
		keyAlg       SignatureAlgorithm
		assert       func(t *testing.T, err error)
	}{
		"signature algorithm mismatch": {
			parameterAlg: RsaPssSha512,
			keyAlg:       EcdsaP256Sha256,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				require.ErrorContains(t, err, "key algorithm rsa-pss-sha512 does not match signature algorithm ecdsa-p256-sha256")
			},
		},
		"signature algorithm matches": {
			parameterAlg: RsaPssSha512,
			keyAlg:       RsaPssSha512,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		"signature algorithm absent": {
			keyAlg: EcdsaP256Sha256,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			if tc.parameterAlg != "" {
				params.Add(string(Alg), string(tc.parameterAlg))
			}

			si, err := parseSignatureInput(httpsfv.InnerList{Params: params})
			require.NoError(t, err)

			exp := &verificationPolicy{}
			err = exp.assertKeyAlgorithm(si, tc.keyAlg)

			tc.assert(t, err)
		})
	}
}
