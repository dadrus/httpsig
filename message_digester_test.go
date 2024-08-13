package httpsig

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContentDigesterVerify(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		msg     *Message
		fromReq bool
		assert  func(t *testing.T, err error)
	}{
		{
			uc: "malformed content-digest header",
			msg: func() *Message {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("content-digest", ",")

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "invalid key format")
			},
		},
		{
			uc: "invalid digest value format",
			msg: func() *Message {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("content-digest", "sha-256")

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrMalformedData)
				require.ErrorContains(t, err, "invalid content-digest value")
			},
		},
		{
			uc: "unknown algorithm",
			msg: func() *Message {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("content-digest", "md5=:eyJoZWxsbyI6ICJ3b3JsZCJ9:")

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoApplicableDigestFound)
			},
		},
		{
			uc: "digest mismatch",
			msg: func() *Message {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("content-digest", "sha-256=:eyJoZWxsbyI6ICJ3b3JsZCJ9:")

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.Error(t, err)
				require.ErrorIs(t, err, ErrVerificationFailed)
				require.ErrorContains(t, err, "digest mismatch")
			},
		},
		{
			uc: "successful request digest verification",
			msg: func() *Message {
				req := httptest.NewRequest(http.MethodGet, "http://example.com/foo", strings.NewReader(`{"hello": "world"}`))
				req.Header.Set("content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "successful response digest verification",
			msg: func() *Message {
				responseWithBody := `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-256=:z0bm/K2/kBiAHdTk/FHlB2NyoHqaTdzCA9k+jeJ0ezA=:
Content-Length: 23

{"message": "good dog"}
`
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://example.com/foo",
					strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)

				resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseWithBody)), req)
				require.NoError(t, err)

				return MessageFromResponse(resp)
			}(),
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
		{
			uc: "successful digest verification of request from response",
			msg: func() *Message {
				responseWithBody := `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 23

{"message": "good dog"}
`
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://example.com/foo",
					strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)
				req.Header.Set("content-digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:")

				resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseWithBody)), req)
				require.NoError(t, err)

				return MessageFromResponse(resp)
			}(),
			fromReq: true,
			assert: func(t *testing.T, err error) {
				t.Helper()

				require.NoError(t, err)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			cd := &contentDigester{fromRequest: tc.fromReq}

			err := cd.verify(tc.msg)

			tc.assert(t, err)
		})
	}
}

func TestContentDigesterUpdate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		uc      string
		msg     *Message
		fromReq bool
		assert  func(t *testing.T, err error, msg *Message)
	}{
		{
			uc: "digest for server-side request",
			msg: MessageFromRequest(httptest.NewRequest(
				http.MethodGet,
				"http://example.com/foo",
				strings.NewReader(`{"hello": "world"}`),
			)),
			assert: func(t *testing.T, err error, msg *Message) {
				t.Helper()

				require.NoError(t, err)

				value := msg.Header.Get("Content-Digest")
				assert.Equal(t, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:", value)
			},
		},
		{
			uc: "digest for client-side request",
			msg: func() *Message {
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://example.com/foo",
					strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)

				return MessageFromRequest(req)
			}(),
			assert: func(t *testing.T, err error, msg *Message) {
				t.Helper()

				require.NoError(t, err)

				value := msg.Header.Get("Content-Digest")
				assert.Equal(t, "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:", value)
			},
		},
		{
			uc: "digest for client-side response",
			msg: func() *Message {
				responseWithBody := `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Length: 23

{"message": "good dog"}
`
				req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "http://example.com/foo",
					strings.NewReader(`{"hello": "world"}`))
				require.NoError(t, err)

				resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(responseWithBody)), req)
				require.NoError(t, err)

				return MessageFromResponse(resp)
			}(),
			assert: func(t *testing.T, err error, msg *Message) {
				t.Helper()

				require.NoError(t, err)

				value := msg.Header.Get("Content-Digest")
				assert.Equal(t, "sha-256=:z0bm/K2/kBiAHdTk/FHlB2NyoHqaTdzCA9k+jeJ0ezA=:, sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:", value)
			},
		},
	} {
		t.Run(tc.uc, func(t *testing.T) {
			cd := &contentDigester{fromRequest: tc.fromReq}

			err := cd.update(tc.msg)

			tc.assert(t, err, tc.msg)
		})
	}
}
