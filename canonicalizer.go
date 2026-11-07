package httpsig

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/dunglas/httpsfv"
)

type canonicalizer interface {
	canonicalize(msg *Message, params *httpsfv.Params) ([]string, error)
}

type canonicalizerFunc func(msg *Message, params *httpsfv.Params) ([]string, error)

func (f canonicalizerFunc) canonicalize(msg *Message, params *httpsfv.Params) ([]string, error) {
	return f(msg, params)
}

func assertRequestOnly(name string, params *httpsfv.Params, isRequest bool) error {
	_, isReq := params.Get("req")

	if isRequest && isReq {
		return fmt.Errorf("%w: 'req' parameter in %s is not valid for requests",
			ErrCanonicalization, name)
	} else if !isRequest && !isReq {
		return fmt.Errorf("%w: %s not valid for responses", ErrCanonicalization, name)
	}

	return nil
}

// assertParameters checks whether parameters are applicable to a
// component and have the required RFC 9421 types and values.
//
//nolint:cyclop
func assertParameters(name string, params *httpsfv.Params, allowed ...string) error {
	if params == nil {
		return nil
	}

	for _, param := range params.Names() {
		if !slices.Contains(allowed, param) {
			return fmt.Errorf("%w: parameter %q is not applicable to %s",
				ErrInvalidComponentIdentifier, param, name)
		}

		value, _ := params.Get(param)

		switch param {
		case "sf", "bs", "tr", "req":
			enabled, ok := value.(bool)
			if !ok || !enabled {
				return fmt.Errorf("%w: %s parameter %q must be true",
					ErrInvalidComponentIdentifier, name, param)
			}
		case "key":
			key, ok := value.(string)
			if !ok || key == "" {
				return fmt.Errorf("%w: %s parameter %q must be a non-empty string",
					ErrInvalidComponentIdentifier, name, param)
			}
		case "name":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%w: %s parameter %q must be a string",
					ErrInvalidComponentIdentifier, name, param)
			}
		default:
			return fmt.Errorf("%w: %s has unsupported parameter %q",
				ErrInvalidComponentIdentifier, name, param)
		}
	}

	return nil
}

//nolint:cyclop
func canonicalizerFor(name string, params *httpsfv.Params) (canonicalizer, error) {
	switch name {
	case "@method":
		return newMethodCanonicalizer(params)
	case "@target-uri":
		return newTargetURICanonicalizer(params)
	case "@authority":
		return newAuthorityCanonicalizer(params)
	case "@scheme":
		return newSchemeCanonicalizer(params)
	case "@request-target":
		return newRequestTargetCanonicalizer(params)
	case "@path":
		return newPathCanonicalizer(params)
	case "@query":
		return newQueryCanonicalizer(params)
	case "@query-param":
		return newQueryParamCanonicalizer(params)
	case "@status":
		return newStatusCodeCanonicalizer(params)
	default:
		if strings.HasPrefix(name, "@") {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedComponentIdentifier, name)
		}

		return newHeaderCanonicalizer(name, params)
	}
}

func newMethodCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@method", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#content-request-method (Section 2.2.1)
		if err := assertRequestOnly("@method", params, msg.IsRequest); err != nil {
			return nil, err
		}

		return []string{msg.Method}, nil
	}), nil
}

func newTargetURICanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@target-uri", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-target-uri (Section 2.2.2)
		if err := assertRequestOnly("@target-uri", params, msg.IsRequest); err != nil {
			return nil, err
		}

		return []string{msg.URL.String()}, nil
	}), nil
}

func newAuthorityCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@authority", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-authority (Section 2.2.3)
		if err := assertRequestOnly("@authority", params, msg.IsRequest); err != nil {
			return nil, err
		}

		host, port, valid := splitHostPort(msg.Authority)
		if !valid {
			return nil, fmt.Errorf("%w: invalid authority %q", ErrCanonicalization, msg.Authority)
		}

		host = normalizeHost(host)
		if port == "" {
			return []string{host}, nil
		}

		port = strings.TrimLeft(port, "0")
		if port == "" {
			port = "0"
		}

		if msg.URL != nil {
			switch strings.ToLower(msg.URL.Scheme) {
			case "http":
				if port == "80" {
					return []string{host}, nil
				}
			case "https":
				if port == "443" {
					return []string{host}, nil
				}
			}
		}

		return []string{host + ":" + port}, nil
	}), nil
}

func newSchemeCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@scheme", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-scheme (Section 2.2.4)
		if err := assertRequestOnly("@scheme", params, msg.IsRequest); err != nil {
			return nil, err
		}

		return []string{strings.ToLower(msg.URL.Scheme)}, nil
	}), nil
}

func newRequestTargetCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@request-target", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-request-target (Section 2.2.5)
		if err := assertRequestOnly("@request-target", params, msg.IsRequest); err != nil {
			return nil, err
		}

		return []string{msg.URL.RequestURI()}, nil
	}), nil
}

func newPathCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@path", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-path (Section 2.2.6)
		if err := assertRequestOnly("@path", params, msg.IsRequest); err != nil {
			return nil, err
		}

		path := msg.URL.EscapedPath()
		if len(path) == 0 || path[0] != '/' {
			path = "/" + path
		}

		return []string{path}, nil
	}), nil
}

func newQueryCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@query", params, "req"); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-query (Section 2.2.7)
		if err := assertRequestOnly("@query", params, msg.IsRequest); err != nil {
			return nil, err
		}

		// absent query params means use `?`
		return []string{"?" + msg.URL.RawQuery}, nil
	}), nil
}

func newQueryParamCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@query-param", params, "req", "name"); err != nil {
		return nil, err
	}

	hasName := false
	if params != nil {
		_, hasName = params.Get("name")
	}

	if !hasName {
		return nil, fmt.Errorf("%w: @query-param requires a 'name' parameter", ErrInvalidComponentIdentifier)
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-query-parameters (Section 2.2.8)
		if err := assertRequestOnly("@query-param", params, msg.IsRequest); err != nil {
			return nil, err
		}

		val, _ := params.Get("name")
		name := val.(string) //nolint: forcetypeassert

		query := msg.queryParams()
		if !query.Has(name) {
			return nil, fmt.Errorf("%w: expected query parameter '%s' not found", ErrCanonicalization, name)
		}

		unescaped := query[name]
		if len(unescaped) > 1 {
			return nil, fmt.Errorf("%w: query parameter '%s' occurs multiple times", ErrCanonicalization, name)
		}

		return []string{url.PathEscape(unescaped[0])}, nil
	}), nil
}

func newStatusCodeCanonicalizer(params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters("@status", params); err != nil {
		return nil, err
	}

	return canonicalizerFunc(func(msg *Message, _ *httpsfv.Params) ([]string, error) {
		// https://www.rfc-editor.org/rfc/rfc9421.html#name-status-code (Section 2.2.9)
		if msg.IsRequest {
			return nil, fmt.Errorf("%w: @status not valid for requests", ErrCanonicalization)
		}

		return []string{strconv.Itoa(msg.StatusCode)}, nil
	}), nil
}

//nolint:cyclop
func newHeaderCanonicalizer(header string, params *httpsfv.Params) (canonicalizer, error) {
	if err := assertParameters(header, params, "sf", "key", "bs", "tr", "req"); err != nil {
		return nil, err
	}

	if params != nil {
		if _, present := params.Get("tr"); present {
			return nil, fmt.Errorf("%w: trailer fields are not supported", ErrInvalidComponentIdentifier)
		}

		_, bs := params.Get("bs")
		_, sf := params.Get("sf")

		_, key := params.Get("key")
		if bs && (sf || key) {
			return nil, fmt.Errorf("%w: cannot combine 'bs' with 'sf' or 'key' on %s",
				ErrInvalidComponentIdentifier, header)
		}
	}

	return canonicalizerFunc(func(msg *Message, params *httpsfv.Params) ([]string, error) {
		serializer, err := newSerializer(params, msg.IsRequest)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrCanonicalization, header, err)
		}

		var hdr http.Header

		if _, isReq := params.Get("req"); !msg.IsRequest && isReq {
			hdr = msg.RequestHeader
		} else {
			hdr = msg.Header
		}

		if len(hdr) == 0 {
			return nil, fmt.Errorf("%w: %s not present in message", ErrCanonicalization, header)
		}

		values := hdr.Values(header)
		if len(values) == 0 {
			// empty values are permitted, but no values are not
			return nil, fmt.Errorf("%w: %s not present in message", ErrCanonicalization, header)
		}

		result, err := serializer.serialize(values)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrCanonicalization, header, err)
		}

		return result, nil
	}), nil
}
