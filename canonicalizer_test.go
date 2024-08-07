package httpsig

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizerFor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  bool
	}{
		{"@method", false},
		{"@target-uri", false},
		{"@authority", false},
		{"@scheme", false},
		{"@request-target", false},
		{"@path", false},
		{"@query", false},
		{"@query-param", false},
		{"@status", false},
		{"@foo", true},
		{"x-foo-bar", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := canonicalizerFor(tc.name)

			if tc.err {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrUnsupportedComponentIdentifier)
				require.ErrorContains(t, err, tc.name)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestCanonicalization(t *testing.T) {
	t.Parallel()

	url1 := "https://example.com/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"
	testURL1, err := url.Parse(url1)
	require.NoError(t, err)

	for _, tc := range []struct {
		uc         string
		identifier string
		message    *Message
		assert     func(t *testing.T, err error, value []string)
	}{
		{
			uc:         "@method for request - valid",
			identifier: `"@method"`,
			message:    &Message{Method: http.MethodGet, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{http.MethodGet}, value)
			},
		},
		{
			uc:         "@method for request - invalid",
			identifier: `"@method";req`,
			message:    &Message{Method: http.MethodGet, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@method for response - valid",
			identifier: `"@method";req`,
			message:    &Message{Method: http.MethodPost, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{http.MethodPost}, value)
			},
		},
		{
			uc:         "@method for response - invalid",
			identifier: `"@method"`,
			message:    &Message{Method: http.MethodGet, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@method not valid for responses")
			},
		},
		{
			uc:         "@target-uri for request - valid",
			identifier: `"@target-uri"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{url1}, value)
			},
		},
		{
			uc:         "@target-uri for request - invalid",
			identifier: `"@target-uri";req`,
			message:    &Message{Method: http.MethodGet, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@target-uri for response - valid",
			identifier: `"@target-uri";req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{url1}, value)
			},
		},
		{
			uc:         "@target-uri for response - invalid",
			identifier: `"@target-uri"`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@target-uri not valid for responses")
			},
		},
		{
			uc:         "@authority for request - valid http without port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com"}, value)
			},
		},
		{
			uc:         "@authority for request - valid https without port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com"}, value)
			},
		},
		{
			uc:         "@authority for request - valid http with default port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:80", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com"}, value)
			},
		},
		{
			uc:         "@authority for request - valid https with default port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com"}, value)
			},
		},
		{
			uc:         "@authority for request - valid http with custom port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:8080", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com:8080"}, value)
			},
		},
		{
			uc:         "@authority for request - valid https with custom port",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:8443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com:8443"}, value)
			},
		},
		{
			uc:         "@authority for request - invalid",
			identifier: `"@authority";req`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@authority for response - valid",
			identifier: `"@authority";req`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				require.Equal(t, []string{"example.com"}, value)
			},
		},
		{
			uc:         "@authority for response - invalid",
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
			},
		},
		{
			uc:         "@scheme for request - valid",
			identifier: `"@scheme"`,
			message:    &Message{URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"http"}, value)
			},
		},
		{
			uc:         "@scheme for request - invalid",
			identifier: `"@scheme";req`,
			message:    &Message{URL: &url.URL{Scheme: "http"}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@scheme for response - valid",
			identifier: `"@scheme";req`,
			message:    &Message{URL: &url.URL{Scheme: "https"}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"https"}, value)
			},
		},
		{
			uc:         "@scheme for response - invalid",
			identifier: `"@scheme"`,
			message:    &Message{URL: &url.URL{Scheme: "https"}, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@scheme not valid for responses")
			},
		},
		{
			uc:         "@request-target for request - valid",
			identifier: `"@request-target"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"}, value)
			},
		},
		{
			uc:         "@request-target for request - invalid",
			identifier: `"@request-target";req`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@request-target for response - valid",
			identifier: `"@request-target";req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"}, value)
			},
		},
		{
			uc:         "@request-target for response - invalid",
			identifier: `"@request-target"`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@request-target not valid for responses")
			},
		},
		{
			uc:         "@path for request - valid without leading slash",
			identifier: `"@path"`,
			message:    &Message{URL: &url.URL{Path: "foo"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"/foo"}, value)
			},
		},
		{
			uc:         "@path for request - valid with leading slash",
			identifier: `"@path"`,
			message:    &Message{URL: &url.URL{Path: "/foo"}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"/foo"}, value)
			},
		},
		{
			uc:         "@path for request - invalid",
			identifier: `"@path";req`,
			message:    &Message{URL: &url.URL{Path: "/foo"}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@path for response - valid",
			identifier: `"@path";req`,
			message:    &Message{URL: &url.URL{Path: "/bar"}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"/bar"}, value)
			},
		},
		{
			uc:         "@path for response - invalid",
			identifier: `"@path"`,
			message:    &Message{URL: &url.URL{Path: "/bar"}, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@path not valid for responses")
			},
		},
		{
			uc:         "@query for request - valid with query present",
			identifier: `"@query"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"?foo=bar&bar=%5Bid%5D"}, value)
			},
		},
		{
			uc:         "@query for request - valid without query",
			identifier: `"@query"`,
			message:    &Message{URL: &url.URL{}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"?"}, value)
			},
		},
		{
			uc:         "@query for request - invalid",
			identifier: `"@query";req`,
			message:    &Message{URL: &url.URL{}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "is not valid for requests")
			},
		},
		{
			uc:         "@query for response - valid",
			identifier: `"@query";req`,
			message:    &Message{URL: &url.URL{}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"?"}, value)
			},
		},
		{
			uc:         "@query for response - invalid",
			identifier: `"@query"`,
			message:    &Message{URL: &url.URL{}, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "@query not valid for responses")
			},
		},
		{
			uc:         "@query-param for request - valid",
			identifier: `"@query-param";name=bar`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"%5Bid%5D"}, value)
			},
		},
		{
			uc:         "@query-param for request - invalid, without required name parameter",
			identifier: `"@query-param"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "named parameter")
			},
		},
		{
			uc:         "@query-param for request - invalid query param escaping",
			identifier: `"@query-param";name=1`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "must be a string")
			},
		},
		{
			uc:         "@query-param for request - invalid, parameter not present in query",
			identifier: `"@query-param";name=moo`,
			message:    &Message{URL: testURL1, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "not found")
			},
		},
		{
			uc:         "@query-param for response - valid",
			identifier: `"@query-param";name=foo;req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"bar"}, value)
			},
		},
		{
			uc:         "@query-param for response - invalid",
			identifier: `"@query-param";name=foo`,
			message:    &Message{URL: testURL1, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "not valid for responses")
			},
		},
		{
			uc:         "@status for response - valid",
			identifier: `"@status"`,
			message:    &Message{StatusCode: http.StatusNotFound, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"404"}, value)
			},
		},
		{
			uc:         "@status for response - invalid",
			identifier: `"@status";req`,
			message:    &Message{StatusCode: http.StatusNotFound, IsRequest: false},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "not valid for requests")
			},
		},
		{
			uc:         "@status for request - invalid",
			identifier: `"@status"`,
			message:    &Message{StatusCode: http.StatusNotFound, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "not valid for requests")
			},
		},
		{
			uc:         "header component for request - invalid, no header present",
			identifier: `"X-Foo-Bar"`,
			message:    &Message{IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "x-foo-bar not present in message")
			},
		},
		{
			uc:         "header component for request - invalid, specified header not present",
			identifier: `"X-Foo-Bar"`,
			message:    &Message{Header: http.Header{"Accept": []string{"application/json"}}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "x-foo-bar not present in message")
			},
		},
		{
			uc:         "header component for request - invalid, bad serialization settings",
			identifier: `"X-Foo-Bar";bs;sf`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "cannot have both")
			},
		},
		{
			uc:         "header component for request - invalid, serialization error",
			identifier: `"X-Foo-Bar";sf;key=foo`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			assert: func(t *testing.T, err error, _ []string) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, "unable to parse")
			},
		},
		{
			uc:         "header component for request - valid",
			identifier: `"X-Foo-Bar"`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"baz"}, value)
			},
		},
		{
			uc:         "header component for response - valid",
			identifier: `"X-Foo-Bar"`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"baz"}, value)
			},
		},
		{
			uc:         "header component for response from request - valid",
			identifier: `"X-Foo-Bar";req`,
			message:    &Message{RequestHeader: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: false},
			assert: func(t *testing.T, err error, value []string) {
				t.Helper()

				require.NoError(t, err)
				assert.Equal(t, []string{"baz"}, value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := canonicalizerFor(strings.ToLower(item.Value.(string)))
			require.NoError(t, err)

			res, err := c.canonicalize(tc.message, normaliseParams(item.Params))

			tc.assert(t, err, res)
		})
	}
}
