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

func TestAssertParameters(t *testing.T) {
	t.Parallel()

	allowed := []string{"sf", "bs", "tr", "req", "key", "name"}
	for uc, tc := range map[string]struct {
		parameter string
		value     any
		allowed   []string
		invalid   bool
	}{
		"no parameters":         {},
		"true sf flag":          {parameter: "sf", value: true, allowed: allowed},
		"false sf flag":         {parameter: "sf", value: false, allowed: allowed, invalid: true},
		"false bs flag":         {parameter: "bs", value: false, allowed: allowed, invalid: true},
		"false req flag":        {parameter: "req", value: false, allowed: allowed, invalid: true},
		"false tr flag":         {parameter: "tr", value: false, allowed: allowed, invalid: true},
		"non-boolean sf flag":   {parameter: "sf", value: int64(1), allowed: allowed, invalid: true},
		"non-boolean bs flag":   {parameter: "bs", value: "true", allowed: allowed, invalid: true},
		"string key":            {parameter: "key", value: "foo", allowed: allowed},
		"empty key":             {parameter: "key", value: "", allowed: allowed, invalid: true},
		"non-string key":        {parameter: "key", value: httpsfv.Token("foo"), allowed: allowed, invalid: true},
		"string name":           {parameter: "name", value: "foo", allowed: allowed},
		"empty name":            {parameter: "name", value: "", allowed: allowed},
		"non-string name":       {parameter: "name", value: httpsfv.Token("foo"), allowed: allowed, invalid: true},
		"unknown parameter":     {parameter: "unknown", value: true, allowed: allowed, invalid: true},
		"allowed parameter":     {parameter: "req", value: true, allowed: []string{"req", "name"}},
		"disallowed parameter":  {parameter: "sf", value: true, allowed: []string{"req"}, invalid: true},
		"no allowed parameters": {parameter: "req", value: true, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			var params *httpsfv.Params
			if tc.parameter != "" {
				params = httpsfv.NewParams()
				params.Add(tc.parameter, tc.value)
			}

			err := assertParameters("x-test", params, tc.allowed...)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				require.ErrorContains(t, err, tc.parameter)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCanonicalizerFor(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		name   string
		params map[string]any
		err    error
	}{
		"@method":         {name: "@method"},
		"@target-uri":     {name: "@target-uri"},
		"@authority":      {name: "@authority"},
		"@scheme":         {name: "@scheme"},
		"@request-target": {name: "@request-target"},
		"@path":           {name: "@path"},
		"@query":          {name: "@query"},
		"@query-param":    {name: "@query-param", params: map[string]any{"name": "foo"}},
		"@status":         {name: "@status"},
		"@foo":            {name: "@foo", err: ErrUnsupportedComponentIdentifier},
		"x-foo-bar":       {name: "x-foo-bar"},
	} {
		t.Run(uc, func(t *testing.T) {
			var params *httpsfv.Params
			if tc.params != nil {
				params = httpsfv.NewParams()
				for name, value := range tc.params {
					params.Add(name, value)
				}
			}

			c, err := canonicalizerFor(tc.name, params)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, c)

				return
			}

			require.NoError(t, err)
			assert.NotNil(t, c)
		})
	}
}

func TestNewMethodCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newMethodCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewTargetURICanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newTargetURICanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewAuthorityCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newAuthorityCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewSchemeCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newSchemeCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewRequestTargetCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newRequestTargetCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewPathCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newPathCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewQueryCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"with req":        {params: map[string]any{"req": true}},
		"with req and sf": {params: map[string]any{"req": true, "sf": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			params := httpsfv.NewParams()
			for name, value := range tc.params {
				params.Add(name, value)
			}

			c, err := newQueryCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewQueryParamCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params map[string]any
		valid  bool
	}{
		"without params":          {},
		"without name":            {params: map[string]any{"req": true}},
		"with name":               {params: map[string]any{"name": "foo"}, valid: true},
		"with name and req":       {params: map[string]any{"name": "foo", "req": true}, valid: true},
		"with encoded name":       {params: map[string]any{"name": "x%2By"}, valid: true},
		"with invalid escape":     {params: map[string]any{"name": "x%GG"}},
		"with literal plus":       {params: map[string]any{"name": "x+y"}},
		"with lowercase escape":   {params: map[string]any{"name": "x%2by"}},
		"with escaped unreserved": {params: map[string]any{"name": "f%6Fo"}},
		"with invalid UTF-8":      {params: map[string]any{"name": "%FF"}},
		"with disallowed sf":      {params: map[string]any{"name": "foo", "sf": true}},
	} {
		t.Run(uc, func(t *testing.T) {
			var params *httpsfv.Params
			if tc.params != nil {
				params = httpsfv.NewParams()
				for name, value := range tc.params {
					params.Add(name, value)
				}
			}

			c, err := newQueryParamCanonicalizer(params)
			if tc.valid {
				require.NoError(t, err)
				assert.NotNil(t, c)
			} else {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			}
		})
	}
}

func TestNewStatusCodeCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params  map[string]any
		invalid bool
	}{
		"without parameters": {},
		"with req":           {params: map[string]any{"req": true}, invalid: true},
	} {
		t.Run(uc, func(t *testing.T) {
			var params *httpsfv.Params
			if tc.params != nil {
				params = httpsfv.NewParams()
				for name, value := range tc.params {
					params.Add(name, value)
				}
			}

			c, err := newStatusCodeCanonicalizer(params)
			if tc.invalid {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, c)
			}
		})
	}
}

func TestNewHeaderCanonicalizer(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		params map[string]any
		valid  bool
	}{
		"without parameters": {valid: true},
		"with req":           {params: map[string]any{"req": true}, valid: true},
		"with sf and key":    {params: map[string]any{"sf": true, "key": "foo"}, valid: true},
		"with bs":            {params: map[string]any{"bs": true}, valid: true},
		"with sf and bs":     {params: map[string]any{"sf": true, "bs": true}},
		"with key and bs":    {params: map[string]any{"key": "foo", "bs": true}},
		"with tr":            {params: map[string]any{"tr": true}},
		"with name":          {params: map[string]any{"name": "foo"}},
	} {
		t.Run(uc, func(t *testing.T) {
			var params *httpsfv.Params
			if tc.params != nil {
				params = httpsfv.NewParams()
				for name, value := range tc.params {
					params.Add(name, value)
				}
			}

			c, err := newHeaderCanonicalizer("x-foo-bar", params)
			if tc.valid {
				require.NoError(t, err)
				assert.NotNil(t, c)
			} else {
				require.ErrorIs(t, err, ErrInvalidComponentIdentifier)
				assert.Nil(t, c)
			}
		})
	}
}

func TestCanonicalizeMethod(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@method for request - valid": {
			identifier: `"@method"`,
			message:    &Message{Method: http.MethodGet, IsRequest: true},
			want:       []string{http.MethodGet},
		},
		"@method for request - invalid": {
			identifier:  `"@method";req`,
			message:     &Message{Method: http.MethodGet, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@method for response - valid": {
			identifier: `"@method";req`,
			message:    &Message{Method: http.MethodPost, IsRequest: false},
			want:       []string{http.MethodPost},
		},
		"@method for response - invalid": {
			identifier:  `"@method"`,
			message:     &Message{Method: http.MethodGet, IsRequest: false},
			errContains: "@method not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newMethodCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeTargetURI(t *testing.T) {
	t.Parallel()

	url1 := "https://example.com/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"
	testURL1, err := url.Parse(url1)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@target-uri for request - valid": {
			identifier: `"@target-uri"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			want:       []string{url1},
		},
		"@target-uri for request - invalid": {
			identifier:  `"@target-uri";req`,
			message:     &Message{Method: http.MethodGet, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@target-uri for response - valid": {
			identifier: `"@target-uri";req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			want:       []string{url1},
		},
		"@target-uri for response - invalid": {
			identifier:  `"@target-uri"`,
			message:     &Message{URL: testURL1, IsRequest: false},
			errContains: "@target-uri not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newTargetURICanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeAuthority(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@authority for request - without port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "ExAmPlE.COM", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - valid http with default port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:80", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - valid https with default port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - valid https with custom port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:8443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com:8443"},
		},
		"@authority for request - ipv6 default port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "[2001:DB8::1]:443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"[2001:db8::1]"},
		},
		"@authority for request - percent-encoded letter": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXA%6Dple.COM", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - padded default port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXAMPLE.com:0443", URL: &url.URL{Scheme: "HTTPS"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - padded non-default port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXAMPLE.com:008443", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com:8443"},
		},
		"@authority for request - empty port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXAMPLE.com:", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com"},
		},
		"@authority for request - zero port": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "example.com:0000", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			want:       []string{"example.com:0"},
		},
		"@authority for request - no default-port removal for other scheme": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXAMPLE.com:443", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			want:       []string{"example.com:443"},
		},
		"@authority for request - no default-port removal without scheme": {
			identifier: `"@authority"`,
			message:    &Message{Authority: "EXAMPLE.com:80", URL: &url.URL{}, IsRequest: true},
			want:       []string{"example.com:80"},
		},
		"@authority for request - invalid non-numeric port": {
			identifier:  `"@authority"`,
			message:     &Message{Authority: "example.com:abc", URL: &url.URL{Scheme: "https"}, IsRequest: true},
			errContains: "invalid authority",
		},
		"@authority for request - invalid": {
			identifier:  `"@authority";req`,
			message:     &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@authority for response - valid": {
			identifier: `"@authority";req`,
			message:    &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: false},
			want:       []string{"example.com"},
		},
		"@authority for response - invalid": {
			identifier:  `"@authority"`,
			message:     &Message{Authority: "example.com", URL: &url.URL{Scheme: "http"}, IsRequest: false},
			errContains: "not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newAuthorityCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeScheme(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@scheme for request - valid": {
			identifier: `"@scheme"`,
			message:    &Message{URL: &url.URL{Scheme: "http"}, IsRequest: true},
			want:       []string{"http"},
		},
		"@scheme for request - invalid": {
			identifier:  `"@scheme";req`,
			message:     &Message{URL: &url.URL{Scheme: "http"}, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@scheme for response - valid": {
			identifier: `"@scheme";req`,
			message:    &Message{URL: &url.URL{Scheme: "https"}, IsRequest: false},
			want:       []string{"https"},
		},
		"@scheme for response - invalid": {
			identifier:  `"@scheme"`,
			message:     &Message{URL: &url.URL{Scheme: "https"}, IsRequest: false},
			errContains: "@scheme not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newSchemeCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeRequestTarget(t *testing.T) {
	t.Parallel()

	url1 := "https://example.com/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"
	testURL1, err := url.Parse(url1)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@request-target for request - valid": {
			identifier: `"@request-target"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			want:       []string{"/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"},
		},
		"@request-target for request - invalid": {
			identifier:  `"@request-target";req`,
			message:     &Message{URL: testURL1, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@request-target for response - valid": {
			identifier: `"@request-target";req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			want:       []string{"/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"},
		},
		"@request-target for response - invalid": {
			identifier:  `"@request-target"`,
			message:     &Message{URL: testURL1, IsRequest: false},
			errContains: "@request-target not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newRequestTargetCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizePath(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@path for request - valid without leading slash": {
			identifier: `"@path"`,
			message:    &Message{URL: &url.URL{Path: "foo"}, IsRequest: true},
			want:       []string{"/foo"},
		},
		"@path for request - valid with leading slash": {
			identifier: `"@path"`,
			message:    &Message{URL: &url.URL{Path: "/foo"}, IsRequest: true},
			want:       []string{"/foo"},
		},
		"@path for request - invalid": {
			identifier:  `"@path";req`,
			message:     &Message{URL: &url.URL{Path: "/foo"}, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@path for response - valid": {
			identifier: `"@path";req`,
			message:    &Message{URL: &url.URL{Path: "/bar"}, IsRequest: false},
			want:       []string{"/bar"},
		},
		"@path for response - invalid": {
			identifier:  `"@path"`,
			message:     &Message{URL: &url.URL{Path: "/bar"}, IsRequest: false},
			errContains: "@path not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newPathCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeQuery(t *testing.T) {
	t.Parallel()

	url1 := "https://example.com/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"
	testURL1, err := url.Parse(url1)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@query for request - valid with query present": {
			identifier: `"@query"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			want:       []string{"?foo=bar&bar=%5Bid%5D"},
		},
		"@query for request - valid without query": {
			identifier: `"@query"`,
			message:    &Message{URL: &url.URL{}, IsRequest: true},
			want:       []string{"?"},
		},
		"@query for request - invalid": {
			identifier:  `"@query";req`,
			message:     &Message{URL: &url.URL{}, IsRequest: true},
			errContains: "is not valid for requests",
		},
		"@query for response - valid": {
			identifier: `"@query";req`,
			message:    &Message{URL: &url.URL{}, IsRequest: false},
			want:       []string{"?"},
		},
		"@query for response - invalid": {
			identifier:  `"@query"`,
			message:     &Message{URL: &url.URL{}, IsRequest: false},
			errContains: "@query not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newQueryCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeQueryParam(t *testing.T) {
	t.Parallel()

	url1 := "https://example.com/foo%2Fbaz/bar%5Bid%5D?foo=bar&bar=%5Bid%5D"
	testURL1, err := url.Parse(url1)
	require.NoError(t, err)

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@query-param for request - valid": {
			identifier: `"@query-param";name="bar"`,
			message:    &Message{URL: testURL1, IsRequest: true},
			want:       []string{"%5Bid%5D"},
		},
		"@query-param for request - percent-encoded plus in name": {
			identifier: `"@query-param";name="x%2By"`,
			message:    &Message{URL: &url.URL{RawQuery: "x%2By=ok"}, IsRequest: true},
			want:       []string{"ok"},
		},
		"@query-param for request - percent-encoded space in name": {
			identifier: `"@query-param";name="x%20y"`,
			message:    &Message{URL: &url.URL{RawQuery: "x+y=ok"}, IsRequest: true},
			want:       []string{"ok"},
		},
		"@query-param for request - empty value": {
			identifier: `"@query-param";name="x"`,
			message:    &Message{URL: &url.URL{RawQuery: "x="}, IsRequest: true},
			want:       []string{""},
		},
		"@query-param for request - valid with duplicate unrelated parameter": {
			identifier: `"@query-param";name="foo"`,
			message:    &Message{URL: &url.URL{RawQuery: "foo=bar&other=one&other=two"}, IsRequest: true},
			want:       []string{"bar"},
		},
		"@query-param for request - invalid, duplicate parameter": {
			identifier:  `"@query-param";name="foo"`,
			message:     &Message{URL: &url.URL{RawQuery: "foo=one&foo=two"}, IsRequest: true},
			errContains: "occurs multiple times",
		},
		"@query-param for request - invalid, duplicate encoded parameter": {
			identifier:  `"@query-param";name="foo"`,
			message:     &Message{URL: &url.URL{RawQuery: "foo=one&%66oo=two"}, IsRequest: true},
			errContains: "occurs multiple times",
		},
		"@query-param for request - invalid, parameter not present in query": {
			identifier:  `"@query-param";name="moo"`,
			message:     &Message{URL: testURL1, IsRequest: true},
			errContains: "not found",
		},
		"@query-param for response - valid": {
			identifier: `"@query-param";name="foo";req`,
			message:    &Message{URL: testURL1, IsRequest: false},
			want:       []string{"bar"},
		},
		"@query-param for response - invalid": {
			identifier:  `"@query-param";name="foo"`,
			message:     &Message{URL: testURL1, IsRequest: false},
			errContains: "not valid for responses",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newQueryParamCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeStatusCode(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"@status for response - valid": {
			identifier: `"@status"`,
			message:    &Message{StatusCode: http.StatusNotFound, IsRequest: false},
			want:       []string{"404"},
		},
		"@status for request - invalid": {
			identifier:  `"@status"`,
			message:     &Message{StatusCode: http.StatusNotFound, IsRequest: true},
			errContains: "not valid for requests",
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newStatusCodeCanonicalizer(item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestCanonicalizeHeader(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		identifier  string
		message     *Message
		want        []string
		errContains string
	}{
		"header component for request - invalid, no header present": {
			identifier:  `"X-Foo-Bar"`,
			message:     &Message{IsRequest: true},
			errContains: "x-foo-bar not present in message",
		},
		"header component for request - invalid, specified header not present": {
			identifier:  `"X-Foo-Bar"`,
			message:     &Message{Header: http.Header{"Accept": []string{"application/json"}}, IsRequest: true},
			errContains: "x-foo-bar not present in message",
		},
		"header component for request - invalid, req parameter": {
			identifier:  `"X-Foo-Bar";req`,
			message:     &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			errContains: "'req' parameter not valid for requests",
		},
		"header component for request - invalid, serialization error": {
			identifier:  `"X-Foo-Bar";sf;key="foo"`,
			message:     &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			errContains: "serialization error",
		},
		"header component for request - valid": {
			identifier: `"X-Foo-Bar"`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: true},
			want:       []string{"baz"},
		},
		"header component for response - valid": {
			identifier: `"X-Foo-Bar"`,
			message:    &Message{Header: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: false},
			want:       []string{"baz"},
		},
		"header component for response from request - valid": {
			identifier: `"X-Foo-Bar";req`,
			message:    &Message{RequestHeader: http.Header{"X-Foo-Bar": []string{"baz"}}, IsRequest: false},
			want:       []string{"baz"},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			item, err := httpsfv.UnmarshalItem([]string{tc.identifier})
			require.NoError(t, err)

			c, err := newHeaderCanonicalizer(strings.ToLower(item.Value.(string)), item.Params)
			require.NoError(t, err)

			value, err := c.canonicalize(tc.message, item.Params)
			if tc.errContains != "" {
				require.ErrorIs(t, err, ErrCanonicalization)
				require.ErrorContains(t, err, tc.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, value)
			}
		})
	}
}

func TestEncodeQueryParam(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		value string
		want  string
	}{
		"empty value":             {},
		"unescaped ASCII":         {value: "AZaz09*-._", want: "AZaz09*-._"},
		"literal plus":            {value: "a+b", want: "a%2Bb"},
		"space":                   {value: "a b", want: "a%20b"},
		"form special characters": {value: "a*b~c&d/e", want: "a*b%7Ec%26d%2Fe"},
		"non-ASCII and newline":   {value: "café\n", want: "caf%C3%A9%0A"},
		"percent sign":            {value: "a%b", want: "a%25b"},
	} {
		t.Run(uc, func(t *testing.T) {
			assert.Equal(t, tc.want, encodeQueryParam(tc.value))
		})
	}
}
