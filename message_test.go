package httpsig

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dunglas/httpsfv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUniqueLabel(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc            string
		label         string
		dict          *httpsfv.Dictionary
		expectedLabel string
	}{
		{
			uc:            "given label not already taken",
			label:         "foo",
			dict:          httpsfv.NewDictionary(),
			expectedLabel: "foo",
		},
		{
			uc:    "given label already taken #1",
			label: "foo",
			dict: func() *httpsfv.Dictionary {
				dict := httpsfv.NewDictionary()
				dict.Add("foo", httpsfv.NewItem("bar"))

				return dict
			}(),
			expectedLabel: "foo1",
		},
		{
			uc:    "given label already taken #2",
			label: "foo",
			dict: func() *httpsfv.Dictionary {
				dict := httpsfv.NewDictionary()
				dict.Add("foo", httpsfv.NewItem("bar"))
				dict.Add("foo1", httpsfv.NewItem("baz"))

				return dict
			}(),
			expectedLabel: "foo2",
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			label := createUniqueLabel(tc.label, tc.dict)

			assert.Equal(t, tc.expectedLabel, label)
		})
	}
}

func TestMessageFromRequest(t *testing.T) {
	t.Parallel()

	expURL, err := url.Parse("http://example.com?foo=bar")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		req    *http.Request
		assert func(t *testing.T, msg *Message)
	}{
		{
			uc: "outbound request without body",
			req: func() *http.Request {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://example.com?foo=bar", nil)
				require.NoError(t, err)

				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.True(t, msg.IsRequest)
				assert.Equal(t, http.MethodGet, msg.Method)
				assert.Equal(t, 0, msg.StatusCode)
				assert.Empty(t, msg.RequestHeader)
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Bar"), []string{"bar"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.Nil(t, msg.RequestBody)
				assert.NotNil(t, msg.Body)

				br, err := msg.Body()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Empty(t, data1)
			},
		},
		{
			uc: "inbound request without body",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "http://example.com?foo=bar", nil)
				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.True(t, msg.IsRequest)
				assert.Equal(t, http.MethodPost, msg.Method)
				assert.Equal(t, 0, msg.StatusCode)
				assert.Empty(t, msg.RequestHeader)
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Bar"), []string{"bar"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.Nil(t, msg.RequestBody)
				assert.NotNil(t, msg.Body)

				br, err := msg.Body()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Empty(t, data1)
			},
		},
		{
			uc: "outbound request with body",
			req: func() *http.Request {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet,
					"http://example.com?foo=bar", strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)

				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.True(t, msg.IsRequest)
				assert.Equal(t, http.MethodGet, msg.Method)
				assert.Equal(t, 0, msg.StatusCode)
				assert.Empty(t, msg.RequestHeader)
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Bar"), []string{"bar"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.Nil(t, msg.RequestBody)
				assert.NotNil(t, msg.Body)

				br, err := msg.Body()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"hello": "world"}`), data1)
			},
		},
		{
			uc: "inbound request with body",
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "http://example.com?foo=bar", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.True(t, msg.IsRequest)
				assert.Equal(t, http.MethodPost, msg.Method)
				assert.Equal(t, 0, msg.StatusCode)
				assert.Empty(t, msg.RequestHeader)
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Bar"), []string{"bar"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.Nil(t, msg.RequestBody)
				assert.NotNil(t, msg.Body)

				br, err := msg.Body()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"hello": "world"}`), data1)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			msg := MessageFromRequest(tc.req)

			tc.assert(t, msg)
		})
	}
}

func TestMessageFromResponse(t *testing.T) {
	t.Parallel()

	responseWithoutBody := `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
Content-Length: 0

`

	responseWithBody := `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:
Content-Length: 23

{"message": "good dog"}
`

	expURL, err := url.Parse("http://example.com?foo=bar")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc     string
		resp   *http.Response
		assert func(t *testing.T, msg *Message)
	}{
		{
			uc: "response without body",
			resp: func() *http.Response {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet,
					"http://example.com?foo=bar", nil)
				require.NoError(t, err)
				req.Header.Set("X-Foo-Bar", "bar")

				resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseWithoutBody)), req)
				require.NoError(t, err)

				return resp
			}(), //nolint:bodyclose
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.False(t, msg.IsRequest)
				assert.Equal(t, http.MethodGet, msg.Method)
				assert.Equal(t, 200, msg.StatusCode)
				assert.Len(t, msg.RequestHeader, 1)
				assert.ElementsMatch(t, msg.RequestHeader.Values("X-Foo-Bar"), []string{"bar"})
				assert.Len(t, msg.Header, 4)
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.NotNil(t, msg.RequestBody)

				br, err := msg.RequestBody()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.RequestBody()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Empty(t, data1)

				assert.NotNil(t, msg.Body)

				br, err = msg.Body()
				require.NoError(t, err)

				data1, err = io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err = io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Empty(t, data1)
			},
		},
		{
			uc: "response with body",
			resp: func() *http.Response {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost,
					"http://example.com?foo=bar", strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)
				req.Header.Set("X-Foo-Bar", "bar")

				resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseWithBody)), req)
				require.NoError(t, err)

				return resp
			}(), //nolint:bodyclose
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.False(t, msg.IsRequest)
				assert.Equal(t, http.MethodPost, msg.Method)
				assert.Equal(t, 200, msg.StatusCode)
				assert.Len(t, msg.RequestHeader, 1)
				assert.ElementsMatch(t, msg.RequestHeader.Values("X-Foo-Bar"), []string{"bar"})
				assert.Len(t, msg.Header, 4)
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.NotNil(t, msg.RequestBody)

				br, err := msg.RequestBody()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.RequestBody()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"hello": "world"}`), data1)

				assert.NotNil(t, msg.Body)

				br, err = msg.Body()
				require.NoError(t, err)

				data1, err = io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err = io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"message": "good dog"}`), data1)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			msg := MessageFromResponse(tc.resp)

			tc.assert(t, msg)
		})
	}
}

func TestMessageForResponse(t *testing.T) {
	t.Parallel()

	expURL, err := url.Parse("http://example.com?foo=bar")
	require.NoError(t, err)

	for _, tc := range []struct {
		uc         string
		req        *http.Request
		respHeader http.Header
		respBody   []byte
		assert     func(t *testing.T, msg *Message)
	}{
		{
			uc: "response without body",
			req: func() *http.Request {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet,
					"http://example.com?foo=bar", strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)
				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			respHeader: http.Header{
				"X-Foo-Baz": []string{"baz"},
			},
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.False(t, msg.IsRequest)
				assert.Equal(t, http.MethodGet, msg.Method)
				assert.Equal(t, 200, msg.StatusCode)
				assert.Len(t, msg.RequestHeader, 1)
				assert.ElementsMatch(t, msg.RequestHeader.Values("X-Foo-Bar"), []string{"bar"})
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Baz"), []string{"baz"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.NotNil(t, msg.RequestBody)

				br, err := msg.RequestBody()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.RequestBody()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"hello": "world"}`), data1)

				assert.NotNil(t, msg.Body)

				br, err = msg.Body()
				require.NoError(t, err)

				data1, err = io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err = io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Empty(t, data1)
			},
		},
		{
			uc: "response with body",
			req: func() *http.Request {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodPost,
					"http://example.com?foo=bar", strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)
				req.Header.Set("X-Foo-Bar", "bar")

				return req
			}(),
			respHeader: http.Header{
				"X-Foo-Baz": []string{"baz"},
			},
			respBody: []byte(`{"message": "good dog"}`),
			assert: func(t *testing.T, msg *Message) {
				t.Helper()

				assert.NotNil(t, msg.Context)
				assert.False(t, msg.IsRequest)
				assert.Equal(t, http.MethodPost, msg.Method)
				assert.Equal(t, 200, msg.StatusCode)
				assert.Len(t, msg.RequestHeader, 1)
				assert.ElementsMatch(t, msg.RequestHeader.Values("X-Foo-Bar"), []string{"bar"})
				assert.Len(t, msg.Header, 1)
				assert.ElementsMatch(t, msg.Header.Values("X-Foo-Baz"), []string{"baz"})
				assert.Equal(t, expURL, msg.URL)
				assert.Equal(t, "example.com", msg.Authority)
				assert.NotNil(t, msg.RequestBody)

				br, err := msg.RequestBody()
				require.NoError(t, err)

				data1, err := io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.RequestBody()
				require.NoError(t, err)

				data2, err := io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"hello": "world"}`), data1)

				assert.NotNil(t, msg.Body)

				br, err = msg.Body()
				require.NoError(t, err)

				data1, err = io.ReadAll(br)
				require.NoError(t, err)

				br, err = msg.Body()
				require.NoError(t, err)

				data2, err = io.ReadAll(br)
				require.NoError(t, err)

				assert.Equal(t, data1, data2)
				assert.Equal(t, []byte(`{"message": "good dog"}`), data1)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			msg := MessageForResponse(tc.req, tc.respHeader, tc.respBody, http.StatusOK)

			tc.assert(t, msg)
		})
	}
}
