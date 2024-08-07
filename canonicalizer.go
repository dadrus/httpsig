package httpsig

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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

func assertResponseOnly(name string, params *httpsfv.Params, isRequest bool) error {
	if _, isReq := params.Get("req"); isRequest || isReq {
		return fmt.Errorf("%w: %s not valid for requests", ErrCanonicalization, name)
	}

	return nil
}

func assertParameter(name string, params *httpsfv.Params, isRequest bool) error {
	if _, forReq := params.Get("req"); forReq && isRequest {
		return fmt.Errorf("%w: 'req' parameter in %s is not valid for requests",
			ErrCanonicalization, name)
	}

	return nil
}

//nolint:cyclop
func canonicalizerFor(name string) (canonicalizer, error) {
	switch name {
	case "@method":
		return canonicalizerFunc(canonicalizeMethod), nil
	case "@target-uri":
		return canonicalizerFunc(canonicalizeTargetURI), nil
	case "@authority":
		return canonicalizerFunc(canonicalizeAuthority), nil
	case "@scheme":
		return canonicalizerFunc(canonicalizeScheme), nil
	case "@request-target":
		return canonicalizerFunc(canonicalizeRequestTarget), nil
	case "@path":
		return canonicalizerFunc(canonicalizePath), nil
	case "@query":
		return canonicalizerFunc(canonicalizeQuery), nil
	case "@query-param":
		return canonicalizerFunc(canonicalizeQueryParam), nil
	case "@status":
		return canonicalizerFunc(canonicalizeStatusCode), nil
	default:
		if strings.HasPrefix(name, "@") {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedComponentIdentifier, name)
		}

		return headerCanonicalizer(name), nil
	}
}

func canonicalizeMethod(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#content-request-method (Section 2.2.1)
	if err := assertRequestOnly("@method", params, msg.IsRequest); err != nil {
		return nil, err
	}

	return []string{msg.Method}, nil
}

func canonicalizeTargetURI(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-target-uri (Section 2.2.2)
	if err := assertRequestOnly("@target-uri", params, msg.IsRequest); err != nil {
		return nil, err
	}

	return []string{msg.URL.String()}, nil
}

func canonicalizeAuthority(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-authority (Section 2.2.3)
	if err := assertRequestOnly("@authority", params, msg.IsRequest); err != nil {
		return nil, err
	}

	host, port, err := net.SplitHostPort(msg.Authority)
	if err != nil {
		// no port, just use the whole thing
		return []string{strings.ToLower(msg.Authority)}, nil //nolint:nilerr
	}

	// default ports shall be omitted
	switch strings.ToLower(msg.URL.Scheme) {
	case "http":
		if port == "80" {
			return []string{strings.ToLower(host)}, nil
		}
	case "https":
		if port == "443" {
			return []string{strings.ToLower(host)}, nil
		}
	}

	return []string{strings.ToLower(msg.Authority)}, nil
}

func canonicalizeScheme(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-scheme (Section 2.2.4)
	if err := assertRequestOnly("@scheme", params, msg.IsRequest); err != nil {
		return nil, err
	}

	return []string{strings.ToLower(msg.URL.Scheme)}, nil
}

func canonicalizeRequestTarget(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-request-target (Section 2.2.5)
	if err := assertRequestOnly("@request-target", params, msg.IsRequest); err != nil {
		return nil, err
	}

	return []string{msg.URL.RequestURI()}, nil
}

func canonicalizePath(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-path (Section 2.2.6)
	if err := assertRequestOnly("@path", params, msg.IsRequest); err != nil {
		return nil, err
	}

	path := msg.URL.EscapedPath()
	if len(path) == 0 || path[0] != '/' {
		path = "/" + path
	}

	return []string{path}, nil
}

func canonicalizeQuery(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-query (Section 2.2.7)
	if err := assertRequestOnly("@query", params, msg.IsRequest); err != nil {
		return nil, err
	}

	// absent query params means use `?`
	return []string{"?" + msg.URL.RawQuery}, nil
}

func canonicalizeQueryParam(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-query-parameters (Section 2.2.8)
	if err := assertRequestOnly("@query-param", params, msg.IsRequest); err != nil {
		return nil, err
	}

	val, ok := params.Get("name")
	if !ok {
		return nil, fmt.Errorf("%w: %w: @query-param must have a named parameter",
			ErrCanonicalization, ErrInvalidComponentIdentifier)
	}

	name, ok := val.(string)
	if !ok {
		return nil, fmt.Errorf("%w: %w: @query-param 'name' must be a string",
			ErrCanonicalization, ErrInvalidComponentIdentifier)
	}

	query := msg.URL.Query()
	if !query.Has(name) {
		return nil, fmt.Errorf("%w: expected query parameter '%s' not found", ErrCanonicalization, name)
	}

	unescaped := query[name]

	values := make([]string, len(unescaped))
	for i, v := range unescaped {
		values[i] = url.PathEscape(v)
	}

	return values, nil
}

func canonicalizeStatusCode(msg *Message, params *httpsfv.Params) ([]string, error) {
	// https://www.rfc-editor.org/rfc/rfc9421.html#name-status-code (Section 2.2.9)
	if err := assertResponseOnly("@status", params, msg.IsRequest); err != nil {
		return nil, err
	}

	return []string{strconv.Itoa(msg.StatusCode)}, nil
}

func headerCanonicalizer(header string) canonicalizerFunc {
	return func(msg *Message, params *httpsfv.Params) ([]string, error) {
		serializer, err := newSerializer(params, msg.IsRequest)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrCanonicalization, header, err)
		}

		var hdr http.Header

		if err := assertParameter(header, params, msg.IsRequest); err != nil {
			return nil, err
		}

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
	}
}
