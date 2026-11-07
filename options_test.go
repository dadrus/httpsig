package httpsig

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithLabelForSigner(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		label        string
		shouldUpdate bool
	}{
		"empty label":     {shouldUpdate: false},
		"not empty label": {label: "foo", shouldUpdate: true},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{label: "test"}

			err := WithLabel(tc.label).applySignerOption(s)
			require.NoError(t, err)

			if tc.shouldUpdate {
				require.Equal(t, tc.label, s.label)
			} else {
				require.Equal(t, "test", s.label)
			}
		})
	}
}

func TestWithLabelForSign(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		label string
		want  string
	}{
		"empty label leaves per-call label unchanged": {want: "initial"},
		"per-call label": {label: "request", want: "request"},
	} {
		t.Run(uc, func(t *testing.T) {
			opts := &signOptions{label: "initial"}

			err := WithLabel(tc.label).applySignOption(opts)

			require.NoError(t, err)
			assert.Equal(t, tc.want, opts.label)
		})
	}
}

func TestWithLabelForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		label string
		exp   string
	}{
		"empty label":  {exp: "foo"},
		"custom label": {label: "bar", exp: "bar"},
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{label: "foo"}

			err := WithLabel(tc.label).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.exp, asb.label)
		})
	}
}

func TestWithTTL(t *testing.T) {
	t.Parallel()

	ttl := 1 * time.Second
	s := &signer{ttl: 30 * time.Second}

	err := WithTTL(ttl).applySignerOption(s)

	require.NoError(t, err)
	require.Equal(t, ttl, s.ttl)
}

func TestWithComponentsForSigner(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifiers []string
		err         error
	}{
		"multiple valid identifier": {identifiers: []string{`"@method";req`, `"@status"`}},
		"unquoted identifier":       {identifiers: []string{"@method"}, err: ErrInvalidComponentIdentifier},
		"invalid identifier":        {identifiers: []string{`"@foo"`}, err: ErrUnsupportedComponentIdentifier},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{}

			err := WithComponents(tc.identifiers...).applySignerOption(s)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Len(t, s.ids, len(tc.identifiers))

				for i, id := range s.ids {
					actual, marshalErr := httpsfv.Marshal(id.Item)
					require.NoError(t, marshalErr)
					assert.Equal(t, tc.identifiers[i], actual)
				}
			}
		})
	}
}

func TestWithComponentsForVerifier(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifiers []string
		err         error
	}{
		"multiple valid identifier": {identifiers: []string{`"@method";req`, `"@status"`}},
		"invalid identifier":        {identifiers: []string{`"@foo"`}, err: ErrUnsupportedComponentIdentifier},
	} {
		t.Run(uc, func(t *testing.T) {
			v := &verifier{}
			exp := &verificationPolicy{}

			err := WithComponents(tc.identifiers...).applyVerifierOption(v, exp, false)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Empty(t, v.tagPolicies)
				require.Len(t, exp.identifiers, len(tc.identifiers))

				for i, id := range exp.identifiers {
					actual, marshalErr := httpsfv.Marshal(id.Item)
					require.NoError(t, marshalErr)
					assert.Equal(t, tc.identifiers[i], actual)
				}
			}
		})
	}
}

func TestWithComponentsForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifiers []string
		assert      func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		"no identifiers provided": {
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.identifiers)
			},
		},
		"invalid identifiers provided": {
			identifiers: []string{`"@foo"`},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		"valid identifiers without content-digest": {
			identifiers: []string{`"@status"`, `"x-foo-bar"`},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				assert.False(t, asb.wantContentDigest)
				assert.Len(t, asb.identifiers, 2)
				assert.Equal(t, "@status", asb.identifiers[0].Value)
				assert.Equal(t, "x-foo-bar", asb.identifiers[1].Value)
			},
		},
		"valid identifiers with content-digest": {
			identifiers: []string{`"@status"`, `"content-digest"`, `"x-foo-bar"`},
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
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{label: "foo"}

			err := WithComponents(tc.identifiers...).applyAcceptSignatureOption(asb)

			tc.assert(t, err, asb)
		})
	}
}

func TestWithTagForSigner(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tag  string
		want string
	}{
		"empty tag leaves current tag unchanged": {want: "initial"},
		"custom tag":                             {tag: "custom", want: "custom"},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{tag: "initial"}

			err := WithTag(tc.tag).applySignerOption(s)

			require.NoError(t, err)
			assert.Equal(t, tc.want, s.tag)
		})
	}
}

func TestWithTagForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, tag := range map[string]string{
		"empty tag":  "",
		"custom tag": "foo",
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithTag(tag).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, tag, asb.tag)
		})
	}
}

func TestWithContentDigestAlgorithm(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		alg DigestAlgorithm
		err error
	}{
		"valid algorithm":   {alg: Sha512},
		"invalid algorithm": {alg: DigestAlgorithm("md4"), err: ErrUnsupportedAlgorithm},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{}

			err := WithContentDigestAlgorithm(tc.alg).applySignerOption(s)

			if tc.err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.alg, s.cdAlg)
			}
		})
	}
}

func TestWithKeyIDForSigner(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		keyID string
		want  string
	}{
		"empty key ID": {want: "initial"},
		"key ID set":   {keyID: "new-id", want: "new-id"},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{keyID: "initial"}

			err := WithKeyID(tc.keyID).applySignerOption(s)

			require.NoError(t, err)
			assert.Equal(t, tc.want, s.keyID)
		})
	}
}

func TestWithKeyIDForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, keyID := range map[string]string{
		"no actual data provided": "",
		"KeyAlg provided":         "test",
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithKeyID(keyID).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, keyID, asb.keyID)
		})
	}
}

func TestWithAlgForSigner(t *testing.T) {
	t.Parallel()

	s := &signer{}

	err := WithAlg().applySignerOption(s)

	require.NoError(t, err)
	assert.True(t, s.includeAlg)
}

func TestWithParameterForSigner(t *testing.T) {
	t.Parallel()

	value := []byte("before")

	for uc, tc := range map[string]struct {
		option   parameterOption
		previous []parameterOption
		assert   func(t *testing.T, err error, s *signer)
	}{
		"extension parameter": {
			option: WithParameter("example", "value"),
			assert: func(t *testing.T, err error, s *signer) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, s.parameters, 1)
				assert.Equal(t, SignatureParameter("example"), s.parameters[0].name)
				assert.Equal(t, "value", s.parameters[0].value)
			},
		},
		"static byte sequence is copied": {
			option: WithParameter("example", value),
			assert: func(t *testing.T, err error, s *signer) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, s.parameters, 1)

				value[0] = 'X'
				assert.Equal(t, []byte("before"), s.parameters[0].value)
			},
		},
		"invalid parameter": {
			option: WithParameter("example", struct{}{}),
			assert: func(t *testing.T, err error, s *signer) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, s.parameters)
			},
		},
		"duplicate parameter": {
			option:   WithParameter("example", "second"),
			previous: []parameterOption{WithParameter("example", "first")},
			assert: func(t *testing.T, err error, s *signer) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				require.Len(t, s.parameters, 1)
				assert.Equal(t, "first", s.parameters[0].value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{}
			for _, previous := range tc.previous {
				require.NoError(t, previous.applySignerOption(s))
			}

			err := tc.option.applySignerOption(s)
			tc.assert(t, err, s)
		})
	}
}

func TestWithParameterForSign(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		option           parameterOption
		previous         []parameterOption
		staticParameters []parameterOption
		assert           func(t *testing.T, err error, opts *signOptions)
	}{
		"per-call nonce": {
			option: WithParameter("nonce", "request-nonce"),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, opts.nonceSet)
				assert.Equal(t, "request-nonce", opts.nonce)
				assert.Empty(t, opts.parameters)
			},
		},
		"additional parameter": {
			option: WithParameter("extension", "value"),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, opts.parameters, 1)
				assert.Equal(t, SignatureParameter("extension"), opts.parameters[0].name)
				assert.Equal(t, "value", opts.parameters[0].value)
			},
		},
		"empty nonce": {
			option: WithParameter("nonce", ""),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.False(t, opts.nonceSet)
				assert.Empty(t, opts.parameters)
			},
		},
		"nonce with incorrect type": {
			option: WithParameter("nonce", Token("value")),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.False(t, opts.nonceSet)
				assert.Empty(t, opts.parameters)
			},
		},
		"invalid nonce string": {
			option: WithParameter("nonce", "bad\nvalue"),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.False(t, opts.nonceSet)
				assert.Empty(t, opts.parameters)
			},
		},
		"invalid extension": {
			option: WithParameter("extension", struct{}{}),
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.False(t, opts.nonceSet)
				assert.Empty(t, opts.parameters)
			},
		},
		"duplicate nonce": {
			option:   WithParameter("nonce", "second"),
			previous: []parameterOption{WithParameter("nonce", "first")},
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Equal(t, "first", opts.nonce)
			},
		},
		"duplicate additional parameter": {
			option:   WithParameter("extension", "second"),
			previous: []parameterOption{WithParameter("extension", "first")},
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				require.Len(t, opts.parameters, 1)
				assert.Equal(t, "first", opts.parameters[0].value)
			},
		},
		"collision with a static parameter": {
			option:           WithParameter("extension", "per-call"),
			staticParameters: []parameterOption{{name: "extension", value: "static"}},
			assert: func(t *testing.T, err error, opts *signOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, opts.parameters)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			opts := &signOptions{staticParameters: tc.staticParameters}
			for _, previous := range tc.previous {
				require.NoError(t, previous.applySignOption(opts))
			}

			err := tc.option.applySignOption(opts)
			tc.assert(t, err, opts)
		})
	}
}

func TestWithParameterForAcceptSignature(t *testing.T) {
	t.Parallel()

	value := []byte("before")

	for uc, tc := range map[string]struct {
		option   parameterOption
		previous []parameterOption
		assert   func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		"extension parameter": {
			option: WithParameter("example", "value"),
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, asb.parameters, 1)
				assert.Equal(t, SignatureParameter("example"), asb.parameters[0].name)
				assert.Equal(t, "value", asb.parameters[0].value)
			},
		},
		"static byte sequence is copied": {
			option: WithParameter("example", value),
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, asb.parameters, 1)

				value[0] = 'X'
				assert.Equal(t, []byte("before"), asb.parameters[0].value)
			},
		},
		"invalid parameter": {
			option: WithParameter("example", struct{}{}),
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, asb.parameters)
			},
		},
		"duplicate parameter": {
			option:   WithParameter("example", "second"),
			previous: []parameterOption{WithParameter("example", "first")},
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				require.Len(t, asb.parameters, 1)
				assert.Equal(t, "first", asb.parameters[0].value)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}
			for _, previous := range tc.previous {
				require.NoError(t, previous.applyAcceptSignatureOption(asb))
			}

			err := tc.option.applyAcceptSignatureOption(asb)
			tc.assert(t, err, asb)
		})
	}
}

func TestWithParameterForAcceptSignatureBuild(t *testing.T) {
	t.Parallel()

	assertInvalid := func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
		t.Helper()

		require.ErrorIs(t, err, ErrParameter)
		assert.False(t, opts.nonceSet)
		assert.Empty(t, opts.parameters)
	}

	for uc, tc := range map[string]struct {
		option           parameterOption
		previous         []parameterOption
		staticParameters []parameterOption
		assert           func(t *testing.T, err error, opts *acceptSignatureBuildOptions)
	}{
		"nonce": {
			option: WithParameter("nonce", "request-nonce"),
			assert: func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
				t.Helper()

				require.NoError(t, err)
				assert.True(t, opts.nonceSet)
				assert.Equal(t, "request-nonce", opts.nonce)
			},
		},
		"extension": {
			option: WithParameter("extension", "value"),
			assert: func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
				t.Helper()

				require.NoError(t, err)
				require.Len(t, opts.parameters, 1)
				assert.Equal(t, "value", opts.parameters[0].value)
			},
		},
		"empty nonce": {
			option: WithParameter("nonce", ""),
			assert: assertInvalid,
		},
		"nonce with incorrect type": {
			option: WithParameter("nonce", Token("value")),
			assert: assertInvalid,
		},
		"invalid nonce string": {
			option: WithParameter("nonce", "bad\nvalue"),
			assert: assertInvalid,
		},
		"invalid extension": {
			option: WithParameter("extension", struct{}{}),
			assert: assertInvalid,
		},
		"duplicate nonce": {
			option:   WithParameter("nonce", "second"),
			previous: []parameterOption{WithParameter("nonce", "first")},
			assert: func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Equal(t, "first", opts.nonce)
			},
		},
		"duplicate extension": {
			option:   WithParameter("extension", "second"),
			previous: []parameterOption{WithParameter("extension", "first")},
			assert: func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				require.Len(t, opts.parameters, 1)
				assert.Equal(t, "first", opts.parameters[0].value)
			},
		},
		"extension conflicts with static parameter": {
			option:           WithParameter("extension", "per-call"),
			staticParameters: []parameterOption{{name: "extension", value: "static"}},
			assert: func(t *testing.T, err error, opts *acceptSignatureBuildOptions) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
				assert.Empty(t, opts.parameters)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			opts := &acceptSignatureBuildOptions{staticParameters: tc.staticParameters}
			for _, previous := range tc.previous {
				require.NoError(t, previous.applyAcceptSignatureBuildOption(opts))
			}

			err := tc.option.applyAcceptSignatureBuildOption(opts)
			tc.assert(t, err, opts)
		})
	}
}

func TestNormalizeParameter(t *testing.T) {
	t.Parallel()

	date := time.Unix(1794000000, 750000000).In(time.FixedZone("UTC+2", 2*60*60))

	for uc, tc := range map[string]struct {
		option  parameterOption
		want    any
		invalid bool
	}{
		"string":                  {option: WithParameter("example", "value"), want: "value"},
		"token":                   {option: WithParameter("example", Token("value")), want: httpsfv.Token("value")},
		"structured fields token": {option: WithParameter("example", httpsfv.Token("value")), want: httpsfv.Token("value")},
		"display string":          {option: WithParameter("example", DisplayString("Grüße")), want: httpsfv.DisplayString("Grüße")},
		"empty display string":    {option: WithParameter("example", DisplayString("")), want: httpsfv.DisplayString("")},
		"date":                    {option: WithParameter("example", date), want: time.Unix(date.Unix(), 0).UTC()},
		"integer":                 {option: WithParameter("example", 42), want: int64(42)},
		"int64":                   {option: WithParameter("example", int64(42)), want: int64(42)},
		"decimal":                 {option: WithParameter("example", 1.5), want: 1.5},
		"boolean":                 {option: WithParameter("example", true), want: true},
		"byte sequence":           {option: WithParameter("example", []byte("value")), want: []byte("value")},
		"reserved created":        {option: WithParameter(Created, int64(1)), invalid: true},
		"reserved expires":        {option: WithParameter(Expires, int64(1)), invalid: true},
		"reserved keyid":          {option: WithParameter(KeyID, "key1"), invalid: true},
		"reserved alg":            {option: WithParameter(Alg, "algorithm"), invalid: true},
		"reserved nonce":          {option: WithParameter(Nonce, "fixed"), invalid: true},
		"reserved tag":            {option: WithParameter(Tag, "app"), invalid: true},
		"invalid name":            {option: WithParameter("invalid name", "value"), invalid: true},
		"invalid string":          {option: WithParameter("example", "bad\nvalue"), invalid: true},
		"invalid token":           {option: WithParameter("example", Token("bad token")), invalid: true},
		"invalid display string":  {option: WithParameter("example", DisplayString("bad\xffvalue")), invalid: true},
		"date out of range":       {option: WithParameter("example", time.Unix(1000000000000000, 0)), invalid: true},
		"unsupported type":        {option: WithParameter("example", struct{}{}), invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			option, err := normalizeParameter(tc.option)
			if tc.invalid {
				require.ErrorIs(t, err, ErrParameter)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.option.name, option.name)
			assert.Equal(t, tc.want, option.value)
		})
	}
}

func TestWithValidityTolerance(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		tolerance time.Duration
		wantError bool
	}{
		"positive tolerance":   {tolerance: time.Minute},
		"zero tolerance":       {},
		"negative tolerance":   {tolerance: -time.Second, wantError: true},
		"minus one nanosecond": {tolerance: -1, wantError: true},
	} {
		t.Run(uc, func(t *testing.T) {
			policy := &verificationPolicy{}

			err := WithValidityTolerance(tc.tolerance).applyVerifierOption(&verifier{}, policy, false)
			if tc.wantError {
				require.ErrorIs(t, err, ErrParameter)
				assert.Nil(t, policy.tolerance)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy.tolerance)
				assert.Equal(t, tc.tolerance, *policy.tolerance)
			}
		})
	}
}

func TestWithMaxAge(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		maxAge    time.Duration
		wantError bool
	}{
		"positive max age":     {maxAge: 15 * time.Minute},
		"zero max age":         {wantError: true},
		"negative max age":     {maxAge: -time.Second, wantError: true},
		"minus one nanosecond": {maxAge: -1, wantError: true},
	} {
		t.Run(uc, func(t *testing.T) {
			policy := &verificationPolicy{}

			err := WithMaxAge(tc.maxAge).applyVerifierOption(&verifier{}, policy, false)
			if tc.wantError {
				require.ErrorIs(t, err, ErrParameter)
				assert.Nil(t, policy.maxAge)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy.maxAge)
				assert.Equal(t, tc.maxAge, *policy.maxAge)
			}
		})
	}
}

func TestWithoutMaxAge(t *testing.T) {
	t.Parallel()

	policy := &verificationPolicy{maxAge: new(30 * time.Second)}

	err := WithoutMaxAge().applyVerifierOption(&verifier{}, policy, false)

	require.NoError(t, err)
	require.NotNil(t, policy.maxAge)
	assert.Zero(t, *policy.maxAge)
}

func TestWithRequiredTag(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts   []VerifierOption
		assert func(t *testing.T, err error, exp *verificationPolicy)
	}{
		"without options": {
			assert: func(t *testing.T, err error, exp *verificationPolicy) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Empty(t, exp.identifiers)
				assert.Nil(t, exp.tolerance)
			},
		},
		"with identifiers only": {
			opts: []VerifierOption{
				WithComponents(`"@status"`),
			},
			assert: func(t *testing.T, err error, exp *verificationPolicy) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				assert.Nil(t, exp.tolerance)
			},
		},
		"with tolerance only": {
			opts: []VerifierOption{
				WithValidityTolerance(5 * time.Minute),
			},
			assert: func(t *testing.T, err error, exp *verificationPolicy) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Empty(t, exp.identifiers)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 5*time.Minute, *exp.tolerance)
			},
		},
		"with all possible options": {
			opts: []VerifierOption{
				WithComponents(`"@status"`),
				WithValidityTolerance(5 * time.Minute),
			},
			assert: func(t *testing.T, err error, exp *verificationPolicy) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Len(t, exp.identifiers, 1)
				assert.Equal(t, "@status", exp.identifiers[0].Value)
				require.NotNil(t, exp.tolerance)
				assert.Equal(t, 5*time.Minute, *exp.tolerance)
			},
		},
		"with unsupported identifier": {
			opts: []VerifierOption{
				WithComponents(`"@foo"`),
			},
			assert: func(t *testing.T, err error, exp *verificationPolicy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.Nil(t, exp)
			},
		},
		"with nested WithRequiredTag": {
			opts: []VerifierOption{
				WithRequiredTag("foo"),
			},
			assert: func(t *testing.T, err error, _ *verificationPolicy) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "WithRequiredTag")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			v := &verifier{tagPolicies: make(map[string]*verificationPolicy)}

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
				return WithRequiredTag("test", tc.opts...).applyVerifierOption(v, nil, false)
			})
			if err == nil {
				require.Len(t, v.tagPolicies, 1)
			}

			tc.assert(t, err, v.tagPolicies["test"])
		})
	}

	t.Run("empty required tag", func(t *testing.T) {
		v := &verifier{tagPolicies: make(map[string]*verificationPolicy)}

		err := WithRequiredTag("").applyVerifierOption(v, nil, false)

		require.ErrorIs(t, err, ErrParameter)
		assert.Empty(t, v.tagPolicies)
	})

	t.Run("with duplicate WithRequiredTag", func(t *testing.T) {
		v := &verifier{tagPolicies: map[string]*verificationPolicy{"foo": {}}}

		err := WithRequiredTag("foo", nil).applyVerifierOption(v, nil, false)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrParameter)
		require.ErrorContains(t, err, "already configured")
	})
}

func TestWithValidateAllSignatures(t *testing.T) {
	t.Parallel()

	v := &verifier{}

	err := WithValidateAllSignatures().applyVerifierOption(v, &verificationPolicy{}, false)

	require.NoError(t, err)
	assert.True(t, v.validateAllSigs)
}

func TestWithCreatedTimestampForVerifier(t *testing.T) {
	t.Parallel()

	for uc, required := range map[string]bool{
		"timestamp required": true,
		"timestamp optional": false,
	} {
		t.Run(uc, func(t *testing.T) {
			exp := &verificationPolicy{}

			err := WithCreatedTimestamp(required).applyVerifierOption(&verifier{}, exp, false)

			require.NoError(t, err)
			require.NotNil(t, exp.reqCreatedTS)
			assert.Equal(t, *exp.reqCreatedTS, required)
		})
	}
}

func TestWithCreatedTimestampForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, requested := range map[string]bool{
		"timestamp requested":     true,
		"timestamp not requested": false,
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{addCreatedTS: !requested}

			err := WithCreatedTimestamp(requested).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, requested, asb.addCreatedTS)
		})
	}
}

func TestWithExpiresTimestampForVerifier(t *testing.T) {
	t.Parallel()

	for uc, required := range map[string]bool{
		"timestamp required": true,
		"timestamp optional": false,
	} {
		t.Run(uc, func(t *testing.T) {
			exp := &verificationPolicy{}

			err := WithExpiresTimestamp(required).applyVerifierOption(&verifier{}, exp, false)

			require.NoError(t, err)
			require.NotNil(t, exp.reqExpiresTS)
			assert.Equal(t, *exp.reqExpiresTS, required)
		})
	}
}

func TestWithExpiresTimestampForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, requested := range map[string]bool{
		"timestamp requested":     true,
		"timestamp not requested": false,
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{addExpiresTS: !requested}

			err := WithExpiresTimestamp(requested).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, requested, asb.addExpiresTS)
		})
	}
}

func TestWithSignatureNegotiation(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts   []SignatureNegotiationOption
		assert func(t *testing.T, err error, asb *AcceptSignatureBuilder)
	}{
		"without options": {
			assert: func(t *testing.T, err error, asb *AcceptSignatureBuilder) {
				t.Helper()

				require.NoError(t, err)

				require.NotNil(t, asb)
				assert.Nil(t, asb.nonceGetter)
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
		"with all possible options": {
			opts: []SignatureNegotiationOption{
				WithLabel("foo"),
				WithNonceGetter(NonceGetterFunc(func(_ context.Context) (string, error) { return "abc", nil })),
				WithSignatureAlgorithm(RsaPssSha512),
				WithKeyID("bar"),
				WithParameter("audience", "service-a"),
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{Sha512, 2}),
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
				require.Len(t, asb.parameters, 1)
				assert.Equal(t, parameterOption{name: "audience", value: "service-a"}, asb.parameters[0])
				// not set by any of the options
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.identifiers)
			},
		},
		"with invalid custom parameter": {
			opts: []SignatureNegotiationOption{WithParameter("created", true)},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.ErrorIs(t, err, ErrParameter)
			},
		},
		"with error while applying the option": {
			opts: []SignatureNegotiationOption{
				WithContentDigestAlgorithmPreferences(AlgorithmPreference{}),
			},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrParameter)
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			v := &verifier{}
			exp := &verificationPolicy{}

			err := WithSignatureNegotiation(tc.opts...).applyVerifierOption(v, exp, false)

			tc.assert(t, err, exp.asb)
		})
	}
}

func TestWithSignatureAlgorithmForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, alg := range map[string]SignatureAlgorithm{
		"no actual data provided": SignatureAlgorithm(""),
		"KeyAlg provided":         RsaPssSha512,
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithSignatureAlgorithm(alg).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, alg, asb.signatureAlgorithm)
		})
	}
}

func TestWithNonceGetterForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		ng  NonceGetter
		exp NonceGetter
	}{
		"nil NonceGetter":    {},
		"custom NonceGetter": {ng: &NonceGetterMock{}, exp: &NonceGetterMock{}},
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{}

			err := WithNonceGetter(tc.ng).applyAcceptSignatureOption(asb)

			require.NoError(t, err)
			assert.Equal(t, tc.exp, asb.nonceGetter)
		})
	}
}

func TestWithNonceGetterNilDoesNotReplaceExisting(t *testing.T) {
	t.Parallel()

	getter := &NonceGetterMock{}
	builder := &AcceptSignatureBuilder{nonceGetter: getter}

	err := WithNonceGetter(nil).applyAcceptSignatureOption(builder)

	require.NoError(t, err)
	assert.Same(t, getter, builder.nonceGetter)
}

func TestWithContentDigestAlgorithmPreferences(t *testing.T) {
	t.Parallel()

	defaultPreference := AlgorithmPreference{Algorithm: Sha256, Preference: 2}.String()

	for uc, tc := range map[string]struct {
		prefs    []AlgorithmPreference
		expErr   error
		expPrefs []string
	}{
		"no preferences provided": {
			expPrefs: []string{defaultPreference},
		},
		"no algorithm provided in a preference": {
			prefs:    []AlgorithmPreference{{Sha256, 0}, {DigestAlgorithm(""), 0}},
			expErr:   ErrParameter,
			expPrefs: []string{defaultPreference},
		},
		"valid options provided": {
			prefs: []AlgorithmPreference{{Sha512, 0}, {Sha256, 1}},
			expPrefs: []string{
				AlgorithmPreference{Sha512, 0}.String(),
				AlgorithmPreference{Sha256, 1}.String(),
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{
				cdAlgPrefs: []string{defaultPreference},
			}

			err := WithContentDigestAlgorithmPreferences(tc.prefs...).applyAcceptSignatureOption(asb)

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
