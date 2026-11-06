package httpsig

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSignatureBase(t *testing.T) {
	t.Parallel()

	// test is based on the non-normative example from
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-creating-the-signature-base

	reqURL, err := url.Parse("http://example.com/foo?param=Value&Pet=dog&Cat=meow")
	require.NoError(t, err)

	msg := &Message{
		Method:    "POST",
		Authority: "example.com",
		URL:       reqURL,
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Digest": []string{"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
			"Content-Length": []string{"18"},
		},
		StatusCode: 0,
		IsRequest:  true,
	}

	keyID := "test-key-rsa-pss"
	created, err := time.Parse(time.RFC1123, "Tue, 20 Apr 2021 02:07:53 GMT")
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		components []string
		assert     func(t *testing.T, err error, base signatureBase)
	}{
		"successful signature base creation": {
			components: []string{
				"@method", "@authority", "@path", "content-digest", "content-length", "content-type",
			},
			assert: func(t *testing.T, err error, base signatureBase) {
				t.Helper()

				require.NoError(t, err)

				expected := `"@method": POST
"@authority": example.com
"@path": /foo
"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
"content-length": 18
"content-type": application/json
"@signature-params": ("@method" "@authority" "@path" "content-digest" "content-length" "content-type");created=1618884473;keyid="test-key-rsa-pss"`

				sigBase := base.marshal()

				assert.Equal(t, expected, string(sigBase))
			},
		},
		"failing for duplicate component identifier": {
			components: []string{
				"@method", "@method",
			},
			assert: func(t *testing.T, err error, _ signatureBase) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "duplicate component identifier")
			},
		},
		"failing for duplicate parameterized component identifier": {
			components: []string{
				`@query-param;name="Pet"`,
				`@query-param;name="Pet"`,
			},
			assert: func(t *testing.T, err error, _ signatureBase) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "duplicate component identifier")
			},
		},
		"failing for duplicate component identifier with reordered parameters": {
			components: []string{
				`content-digest;key="sha-512";sf`,
				`content-digest;sf;key="sha-512"`,
			},
			assert: func(t *testing.T, err error, _ signatureBase) {
				t.Helper()

				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "duplicate component identifier")
			},
		},
		"failing for unknown component identifier": {
			components: []string{"@status"},
			assert: func(t *testing.T, err error, _ signatureBase) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@status")
			},
		},
		"allowing same component identifier with different parameters": {
			components: []string{
				`@query-param;name="Pet"`,
				`@query-param;name="Cat"`,
			},
			assert: func(t *testing.T, err error, base signatureBase) {
				t.Helper()

				require.NoError(t, err)

				expected := `"@query-param";name="Pet": dog
"@query-param";name="Cat": meow
"@signature-params": ("@query-param";name="Pet" "@query-param";name="Cat");created=1618884473;keyid="test-key-rsa-pss"`

				sigBase := base.marshal()

				assert.Equal(t, expected, string(sigBase))
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			identifiers, err := toComponentIdentifiers(tc.components)
			require.NoError(t, err)

			params := httpsfv.NewParams()
			params.Add(string(Created), created.Unix())
			params.Add(string(KeyID), keyID)

			si := newSignatureInput(identifiers, params)

			sigBase, err := newSignatureBase(msg, si, nil)

			tc.assert(t, err, sigBase)
		})
	}
}

func TestNewSignatureBaseWithPreparedIdentifiers(t *testing.T) {
	t.Parallel()

	for name, identifiers := range map[string][]string{
		"no covered components":        {},
		"simple component":             {"@method"},
		"several components":           {"@method", "@authority", "x-example"},
		"parameterized components":     {"@method", `@query-param;name="Pet"`, `@query-param;name="Cat"`},
		"duplicate component":          {"@method", "@method"},
		"duplicate parameterized item": {`@query-param;name="Pet"`, `@query-param;name="Pet"`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sgnr, err := NewSigner(
				Key{Algorithm: HmacSha256, Material: []byte("test-hmac-key")},
				WithComponents(identifiers...),
			)
			require.NoError(t, err)

			s := sgnr.(*signer)

			require.Len(t, s.serializedIdentifiers, len(s.ids))

			for i, id := range s.ids {
				want, marshalErr := httpsfv.Marshal(id.Item)
				require.NoError(t, marshalErr)
				assert.Equal(t, want, s.serializedIdentifiers[i])
			}

			msg := &Message{
				Method: "GET", Authority: "example.com",
				URL:       &url.URL{Path: "/foo", RawQuery: "Pet=dog&Cat=meow"},
				Header:    http.Header{"X-Example": []string{"value"}},
				IsRequest: true,
			}
			input := s.signatureInput(signOptions{})
			uncached, uncachedErr := newSignatureBase(msg, input, nil)
			prepared, preparedErr := newSignatureBase(msg, input, s.serializedIdentifiers)

			if uncachedErr != nil {
				require.ErrorIs(t, preparedErr, ErrMalformedData)
				require.ErrorIs(t, uncachedErr, ErrMalformedData)

				return
			}

			require.NoError(t, preparedErr)
			assert.Equal(t, uncached.marshal(), prepared.marshal())
			assert.Equal(t, uncached.components(), prepared.components())
		})
	}
}

func TestNewSignatureBaseWithInvalidPreparedIdentifierCount(t *testing.T) {
	t.Parallel()

	ids, err := toComponentIdentifiers([]string{"@method"})
	require.NoError(t, err)

	input := newSignatureInput(ids, httpsfv.NewParams())
	msg := &Message{Method: "GET", IsRequest: true}

	_, err = newSignatureBase(msg, input, []string{"one", "two"})

	require.ErrorIs(t, err, ErrMalformedData)
}

func TestSignatureBaseMarshal(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		base signatureBase
		want string
	}{
		"empty": {},
		"signature parameters only": {
			base: signatureBase{signatureParams: `("@method");created=123`},
			want: `"@signature-params": ("@method");created=123`,
		},
		"single component without parameters": {
			base: signatureBase{entries: []serializedComponent{{identifier: `"@method"`, value: "GET"}}},
			want: `"@method": GET`,
		},
		"multiple components without parameters": {
			base: signatureBase{entries: []serializedComponent{
				{identifier: `"@authority"`, value: "foo.bar"},
				{identifier: `"@method"`, value: "GET"},
			}},
			want: "\"@authority\": foo.bar\n\"@method\": GET",
		},
		"empty and UTF-8 component values with parameters": {
			base: signatureBase{
				entries: []serializedComponent{
					{identifier: `"x-empty"`, value: ""},
					{identifier: `"x-name"`, value: "Grüße"},
				},
				signatureParams: `("x-empty" "x-name");created=123`,
			},
			want: "\"x-empty\": \n\"x-name\": Grüße\n\"@signature-params\": (\"x-empty\" \"x-name\");created=123",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, string(tc.base.marshal()))
		})
	}
}

func TestSignatureBaseComponents(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		names           []string
		entries         []serializedComponent
		signatureParams string
		expected        map[string]string
	}{
		"empty signature base": {
			expected: map[string]string{},
		},
		"excluding signature parameters": {
			signatureParams: `("@method");created=123`,
			expected:        map[string]string{},
		},
		"simple component identifiers": {
			names: []string{"@method", "@authority", "user-agent"},
			entries: []serializedComponent{
				{identifier: `"@method"`, value: "GET"},
				{identifier: `"@authority"`, value: "example.com"},
				{identifier: `"user-agent"`, value: "ExampleBot/1.0"},
			},
			signatureParams: `("@method" "@authority" "user-agent")`,
			expected: map[string]string{
				"@method":    "GET",
				"@authority": "example.com",
				"user-agent": "ExampleBot/1.0",
			},
		},
		"parameterized component identifiers": {
			names: []string{"@query-param", "@query-param", "signature-agent"},
			entries: []serializedComponent{
				{identifier: `"@query-param";name="Pet"`, value: "dog"},
				{identifier: `"@query-param";name="Cat"`, value: "meow"},
				{identifier: `"signature-agent";key="sig1"`, value: `"https://bots.example.com";type=cimd`},
			},
			expected: map[string]string{
				`@query-param;name="Pet"`:    "dog",
				`@query-param;name="Cat"`:    "meow",
				`signature-agent;key="sig1"`: `"https://bots.example.com";type=cimd`,
			},
		},
		"boolean identifier parameter": {
			names: []string{"content-type"},
			entries: []serializedComponent{
				{identifier: `"content-type";sf`, value: "application/json"},
			},
			expected: map[string]string{
				"content-type;sf": "application/json",
			},
		},
		"multiple canonicalized values": {
			names: []string{"x-example"},
			entries: []serializedComponent{
				{identifier: `"x-example"`, value: "first, second, third"},
			},
			expected: map[string]string{
				"x-example": "first, second, third",
			},
		},
		"empty canonicalized value": {
			names: []string{"x-empty"},
			entries: []serializedComponent{
				{identifier: `"x-empty"`, value: ""},
			},
			expected: map[string]string{
				"x-empty": "",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			identifiers := make([]*componentIdentifier, len(tc.names))
			for i, name := range tc.names {
				identifiers[i] = &componentIdentifier{Item: httpsfv.NewItem(name)}
			}

			base := signatureBase{
				input:           &signatureInput{identifiers: identifiers},
				entries:         tc.entries,
				signatureParams: tc.signatureParams,
			}

			components := base.components()

			assert.Equal(t, tc.expected, components)
		})
	}
}
