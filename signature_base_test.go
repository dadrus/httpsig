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

				sigBase, err := base.marshal()
				require.NoError(t, err)

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

				sigBase, err := base.marshal()
				require.NoError(t, err)

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

	msg := &Message{Method: "GET", Authority: "foo.bar", IsRequest: true}

	ci, err := toComponentIdentifiers([]string{"@authority", "@method"})
	require.NoError(t, err)

	list := make(signatureBase, len(ci))

	for i, id := range ci {
		c, err := id.createComponent(msg)
		require.NoError(t, err)

		list[i] = c
	}

	res, err := list.marshal()
	require.NoError(t, err)

	assert.Equal(t, "\"@authority\": foo.bar\n\"@method\": GET", string(res))
}

func TestSignatureBaseComponents(t *testing.T) {
	t.Parallel()

	petParams := httpsfv.NewParams()
	petParams.Add("name", "Pet")

	catParams := httpsfv.NewParams()
	catParams.Add("name", "Cat")

	agentParams := httpsfv.NewParams()
	agentParams.Add("key", "sig1")

	sfParams := httpsfv.NewParams()
	sfParams.Add("sf", true)

	for uc, tc := range map[string]struct {
		base     signatureBase
		expected map[string]string
	}{
		"empty signature base": {
			base:     signatureBase{},
			expected: map[string]string{},
		},
		"excluding signature parameters": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("@signature-params"),
					},
					value: []string{`("@method");created=123`},
				},
			},
			expected: map[string]string{},
		},
		"simple component identifiers": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("@method"),
					},
					value: []string{"GET"},
				},
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("@authority"),
					},
					value: []string{"example.com"},
				},
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("user-agent"),
					},
					value: []string{"ExampleBot/1.0"},
				},
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("@signature-params"),
					},
					value: []string{
						`("@method" "@authority" "user-agent")`,
					},
				},
			},
			expected: map[string]string{
				"@method":    "GET",
				"@authority": "example.com",
				"user-agent": "ExampleBot/1.0",
			},
		},
		"parameterized component identifiers": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.Item{
							Value:  "@query-param",
							Params: petParams,
						},
					},
					value: []string{"dog"},
				},
				{
					key: &componentIdentifier{
						Item: httpsfv.Item{
							Value:  "@query-param",
							Params: catParams,
						},
					},
					value: []string{"meow"},
				},
				{
					key: &componentIdentifier{
						Item: httpsfv.Item{
							Value:  "signature-agent",
							Params: agentParams,
						},
					},
					value: []string{
						`"https://bots.example.com";type=cimd`,
					},
				},
			},
			expected: map[string]string{
				`@query-param;name="Pet"`:    "dog",
				`@query-param;name="Cat"`:    "meow",
				`signature-agent;key="sig1"`: `"https://bots.example.com";type=cimd`,
			},
		},
		"boolean identifier parameter": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.Item{
							Value:  "content-type",
							Params: sfParams,
						},
					},
					value: []string{"application/json"},
				},
			},
			expected: map[string]string{
				"content-type;sf": "application/json",
			},
		},
		"multiple canonicalized values": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("x-example"),
					},
					value: []string{
						"first",
						"second",
						"third",
					},
				},
			},
			expected: map[string]string{
				"x-example": "first, second, third",
			},
		},
		"empty canonicalized value": {
			base: signatureBase{
				{
					key: &componentIdentifier{
						Item: httpsfv.NewItem("x-empty"),
					},
					value: []string{""},
				},
			},
			expected: map[string]string{
				"x-empty": "",
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			t.Parallel()

			components, err := tc.base.components()
			require.NoError(t, err)

			assert.Equal(t, tc.expected, components)
		})
	}
}
