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

	for _, tc := range []struct {
		uc         string
		components []string
		assert     func(t *testing.T, err error, base signatureBase)
	}{
		{
			uc: "successful signature base creation",
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
		{
			uc: "failing for duplicate component identifier",
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
		{
			uc: "failing for duplicate parameterized component identifier",
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
		{
			uc:         "failing for unknown component identifier",
			components: []string{"@status"},
			assert: func(t *testing.T, err error, _ signatureBase) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@status")
			},
		},
		{
			uc: "allowing same component identifier with different parameters",
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
		t.Run(tc.uc, func(t *testing.T) {
			identifiers, err := toComponentIdentifiers(tc.components)
			require.NoError(t, err)

			params := httpsfv.NewParams()
			params.Add(string(Created), created.Unix())
			params.Add(string(KeyID), keyID)

			si := newSignatureInput(identifiers, params)

			sigBase, err := newSignatureBase(si, msg)

			tc.assert(t, err, sigBase)
		})
	}
}

func TestSignatureBaseMarshal(t *testing.T) {
	t.Parallel()

	base := signatureBase{
		entries: []serializedComponent{
			{identifier: `"@authority"`, value: "foo.bar"},
			{identifier: `"@method"`, value: "GET"},
		},
	}

	res := base.marshal()

	assert.Equal(t, "\"@authority\": foo.bar\n\"@method\": GET", string(res))
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
