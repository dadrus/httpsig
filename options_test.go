package httpsig

import (
	"context"
	"fmt"
	"strings"
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
		"multiple valid identifier": {identifiers: []string{"@status;req", "@method"}},
		"invalid identifier":        {identifiers: []string{"@foo"}, err: ErrUnsupportedComponentIdentifier},
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
					vals := strings.Split(tc.identifiers[i], ";")
					assert.Equal(t, vals[0], id.Value)
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
		"multiple valid identifier": {identifiers: []string{"@status;req", "@method"}},
		"invalid identifier":        {identifiers: []string{"@foo"}, err: ErrUnsupportedComponentIdentifier},
	} {
		t.Run(uc, func(t *testing.T) {
			v := &verifier{}
			exp := &expectations{}

			err := WithComponents(tc.identifiers...).applyVerifierOption(v, exp, false)

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
			identifiers: []string{"@foo"},
			assert: func(t *testing.T, err error, _ *AcceptSignatureBuilder) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
			},
		},
		"valid identifiers without content-digest": {
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
		"valid identifiers with content-digest": {
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

	t.Run("supported parameter types", func(t *testing.T) {
		for uc, tc := range map[string]struct {
			value any
			want  any
		}{
			"string":        {value: "value", want: "value"},
			"token":         {value: Token("value"), want: httpsfv.Token("value")},
			"integer":       {value: 42, want: int64(42)},
			"int64":         {value: int64(42), want: int64(42)},
			"decimal":       {value: 1.5, want: 1.5},
			"boolean":       {value: true, want: true},
			"byte sequence": {value: []byte("value"), want: []byte("value")},
		} {
			t.Run(uc, func(t *testing.T) {
				s := &signer{}

				err := WithParameter("example", tc.value).applySignerOption(s)

				require.NoError(t, err)
				require.Len(t, s.parameters, 1)
				assert.Equal(t, "example", s.parameters[0].name)
				assert.Equal(t, tc.want, s.parameters[0].value)
			})
		}
	})

	t.Run("static byte sequence is copied", func(t *testing.T) {
		value := []byte("before")
		s := &signer{}

		err := WithParameter("example", value).applySignerOption(s)
		require.NoError(t, err)

		value[0] = 'X'
		assert.Equal(t, []byte("before"), s.parameters[0].value)
	})

	for uc, param := range map[string]parameterOption{
		"reserved parameter": WithParameter("created", int64(1)),
		"static nonce":       WithParameter("nonce", "fixed"),
		"invalid name":       WithParameter("invalid name", "value"),
		"invalid string":     WithParameter("example", "bad\nvalue"),
		"unsupported type":   WithParameter("example", struct{}{}),
	} {
		t.Run(uc, func(t *testing.T) {
			s := &signer{}

			err := param.applySignerOption(s)

			require.ErrorIs(t, err, ErrParameter)
			assert.Empty(t, s.parameters)
		})
	}

	t.Run("duplicate parameter", func(t *testing.T) {
		s := &signer{}
		require.NoError(t, WithParameter("example", "first").applySignerOption(s))

		err := WithParameter("example", "second").applySignerOption(s)

		require.ErrorIs(t, err, ErrParameter)
		require.Len(t, s.parameters, 1)
		assert.Equal(t, "first", s.parameters[0].value)
	})
}

func TestWithParameterForSign(t *testing.T) {
	t.Parallel()

	t.Run("per-call nonce", func(t *testing.T) {
		opts := &signOptions{}

		err := WithParameter("nonce", "request-nonce").applySignOption(opts)

		require.NoError(t, err)
		assert.True(t, opts.nonceSet)
		assert.Equal(t, "request-nonce", opts.nonce)
		assert.Empty(t, opts.parameters)
	})

	t.Run("additional parameter", func(t *testing.T) {
		opts := &signOptions{}

		err := WithParameter("extension", Token("value")).applySignOption(opts)

		require.NoError(t, err)
		require.Len(t, opts.parameters, 1)
		assert.Equal(t, "extension", opts.parameters[0].name)
		assert.Equal(t, httpsfv.Token("value"), opts.parameters[0].value)
	})

	for uc, param := range map[string]parameterOption{
		"empty nonce":               WithParameter("nonce", ""),
		"nonce with incorrect type": WithParameter("nonce", Token("value")),
		"invalid nonce string":      WithParameter("nonce", "bad\nvalue"),
		"reserved parameter":        WithParameter("expires", int64(1)),
	} {
		t.Run(uc, func(t *testing.T) {
			opts := &signOptions{}

			err := param.applySignOption(opts)

			require.ErrorIs(t, err, ErrParameter)
			assert.False(t, opts.nonceSet)
			assert.Empty(t, opts.parameters)
		})
	}

	t.Run("duplicate nonce", func(t *testing.T) {
		opts := &signOptions{}
		require.NoError(t, WithParameter("nonce", "first").applySignOption(opts))

		err := WithParameter("nonce", "second").applySignOption(opts)

		require.ErrorIs(t, err, ErrParameter)
		assert.Equal(t, "first", opts.nonce)
	})

	t.Run("duplicate additional parameter", func(t *testing.T) {
		opts := &signOptions{}
		require.NoError(t, WithParameter("extension", "first").applySignOption(opts))

		err := WithParameter("extension", "second").applySignOption(opts)

		require.ErrorIs(t, err, ErrParameter)
		require.Len(t, opts.parameters, 1)
		assert.Equal(t, "first", opts.parameters[0].value)
	})

	t.Run("collision with a static parameter", func(t *testing.T) {
		opts := &signOptions{
			staticParameters: []parameterOption{{name: "extension", value: "static"}},
		}

		err := WithParameter("extension", "per-call").applySignOption(opts)

		require.ErrorIs(t, err, ErrParameter)
		assert.Empty(t, opts.parameters)
	})
}

func TestWithParameterForAcceptSignatureBuild(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		param   parameterOption
		want    string
		wantErr bool
	}{
		"nonce":                     {param: WithParameter("nonce", "request-nonce"), want: "request-nonce"},
		"other parameter":           {param: WithParameter("extension", "value"), wantErr: true},
		"empty nonce":               {param: WithParameter("nonce", ""), wantErr: true},
		"nonce with incorrect type": {param: WithParameter("nonce", Token("value")), wantErr: true},
		"invalid nonce string":      {param: WithParameter("nonce", "bad\nvalue"), wantErr: true},
	} {
		t.Run(uc, func(t *testing.T) {
			opts := &acceptSignatureBuildOptions{}

			err := tc.param.applyAcceptSignatureBuildOption(opts)

			if tc.wantErr {
				require.ErrorIs(t, err, ErrParameter)
				assert.False(t, opts.nonceSet)

				return
			}

			require.NoError(t, err)
			assert.True(t, opts.nonceSet)
			assert.Equal(t, tc.want, opts.nonce)
		})
	}

	t.Run("duplicate nonce", func(t *testing.T) {
		opts := &acceptSignatureBuildOptions{}
		require.NoError(t, WithParameter("nonce", "first").applyAcceptSignatureBuildOption(opts))

		err := WithParameter("nonce", "second").applyAcceptSignatureBuildOption(opts)

		require.ErrorIs(t, err, ErrParameter)
		assert.Equal(t, "first", opts.nonce)
	})
}

func TestWithValidityTolerance(t *testing.T) {
	t.Parallel()

	v := &verifier{}
	exp := &expectations{}

	err := WithValidityTolerance(1*time.Minute).applyVerifierOption(v, exp, false)
	require.NoError(t, err)

	assert.Empty(t, v.tagExpectations)
	assert.Equal(t, 1*time.Minute, exp.tolerance)
}

func TestWithMaxAge(t *testing.T) {
	t.Parallel()

	v := &verifier{}
	exp := &expectations{}

	err := WithMaxAge(15*time.Minute).applyVerifierOption(v, exp, false)
	require.NoError(t, err)

	assert.Equal(t, 15*time.Minute, exp.maxAge)
}

func TestWithRequiredTag(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		opts   []VerifierOption
		assert func(t *testing.T, err error, exp *expectations)
	}{
		"without options": {
			assert: func(t *testing.T, err error, exp *expectations) {
				t.Helper()

				require.NoError(t, err)
				require.NotNil(t, exp)
				assert.Empty(t, exp.identifiers)
				assert.Equal(t, time.Duration(-1), exp.tolerance) //nolint:testifylint
			},
		},
		"with identifiers only": {
			opts: []VerifierOption{
				WithComponents("@status"),
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
		"with tolerance only": {
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
		"with all possible options": {
			opts: []VerifierOption{
				WithComponents("@status"),
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
		"with unsupported identifier": {
			opts: []VerifierOption{
				WithComponents("@foo"),
			},
			assert: func(t *testing.T, err error, exp *expectations) {
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
			assert: func(t *testing.T, err error, _ *expectations) {
				t.Helper()

				require.Error(t, err)
				require.ErrorContains(t, err, "WithRequiredTag")
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
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
				return WithRequiredTag("test", tc.opts...).applyVerifierOption(v, nil, false)
			})
			if err == nil {
				require.Len(t, v.tagExpectations, 1)
			}

			tc.assert(t, err, v.tagExpectations["test"])
		})
	}

	t.Run("empty required tag", func(t *testing.T) {
		v := &verifier{tagExpectations: make(map[string]*expectations)}

		err := WithRequiredTag("").applyVerifierOption(v, nil, false)

		require.ErrorIs(t, err, ErrParameter)
		assert.Empty(t, v.tagExpectations)
	})

	t.Run("with duplicate WithRequiredTag", func(t *testing.T) {
		v := &verifier{tagExpectations: map[string]*expectations{"foo": {}}}

		err := WithRequiredTag("foo", nil).applyVerifierOption(v, nil, false)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrParameter)
		require.ErrorContains(t, err, "already configured")
	})
}

func TestWithValidateAllSignatures(t *testing.T) {
	t.Parallel()

	v := &verifier{}

	err := WithValidateAllSignatures().applyVerifierOption(v, &expectations{}, false)

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
			exp := &expectations{}

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

func TestWithExpiredTimestampForVerifier(t *testing.T) {
	t.Parallel()

	for uc, required := range map[string]bool{
		"timestamp required": true,
		"timestamp optional": false,
	} {
		t.Run(uc, func(t *testing.T) {
			exp := &expectations{}

			err := WithExpiredTimestamp(required).applyVerifierOption(&verifier{}, exp, false)

			require.NoError(t, err)
			require.NotNil(t, exp.reqExpiresTS)
			assert.Equal(t, *exp.reqExpiresTS, required)
		})
	}
}

func TestWithExpiredTimestampForAcceptSignature(t *testing.T) {
	t.Parallel()

	for uc, requested := range map[string]bool{
		"timestamp requested":     true,
		"timestamp not requested": false,
	} {
		t.Run(uc, func(t *testing.T) {
			asb := &AcceptSignatureBuilder{addExpiresTS: !requested}

			err := WithExpiredTimestamp(requested).applyAcceptSignatureOption(asb)

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
				// not set by any of the options
				assert.True(t, asb.addCreatedTS)
				assert.True(t, asb.addExpiresTS)
				assert.False(t, asb.wantContentDigest)
				assert.Empty(t, asb.tag)
				assert.Empty(t, asb.identifiers)
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
			exp := &expectations{}

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
