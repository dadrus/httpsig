package httpsig

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/dunglas/httpsfv"
)

// MessageFromRequest creates a Message for signing or verifying an HTTP
// request. Request headers are cloned. If the body must be read and req.GetBody
// is unavailable, the original body is buffered and replaced so it remains
// readable. Callers must enforce size limits for untrusted request bodies.
func MessageFromRequest(req *http.Request) *Message {
	var (
		getBody      func() (io.ReadCloser, error)
		bodySnapshot []byte
	)

	// for client requests req.Body can be nil, but not for server requests
	switch {
	case req.GetBody == nil && req.Body == nil:
		getBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	case req.GetBody != nil:
		getBody = req.GetBody
	default:
		getBody = func() (io.ReadCloser, error) {
			if len(bodySnapshot) != 0 {
				return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
			}

			save, newBody, err := drainBody(req.Body)
			if err != nil {
				return nil, err
			}

			req.Body = newBody
			bodySnapshot = save

			return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
		}
	}

	return &Message{
		Method:    req.Method,
		Authority: req.Host,
		URL:       req.URL,
		Header:    req.Header.Clone(),
		Body:      getBody,
		IsRequest: true,
		Context:   req.Context(),
	}
}

// MessageFromResponse creates a Message from a received HTTP response and
// its associated request. Response and request headers are cloned. The
// response body may be buffered and restored when a covered component needs
// it. The request body is available for ;req components only when the
// associated request has a GetBody function.
func MessageFromResponse(rw *http.Response) *Message {
	var bodySnapshot []byte

	getResponseBody := func() (io.ReadCloser, error) {
		if len(bodySnapshot) != 0 {
			return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
		}

		save, newBody, err := drainBody(rw.Body)
		if err != nil {
			return nil, err
		}

		rw.Body = newBody
		bodySnapshot = save

		return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
	}

	var getRequestBody func() (io.ReadCloser, error)

	if rw.Request.GetBody != nil {
		getRequestBody = rw.Request.GetBody
	} else {
		getRequestBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	}

	return &Message{
		Method:        rw.Request.Method,
		Authority:     rw.Request.Host,
		URL:           rw.Request.URL,
		Header:        rw.Header.Clone(),
		Body:          getResponseBody,
		StatusCode:    rw.StatusCode,
		RequestHeader: rw.Request.Header.Clone(),
		RequestBody:   getRequestBody,
		IsRequest:     false,
		Context:       rw.Request.Context(),
	}
}

// MessageForResponse creates a Message for signing a response to req.
// It clones the response and request headers and makes the supplied body
// available for Content-Digest and other covered components. The request
// body may be buffered and restored when a ;req component requires it.
func MessageForResponse(req *http.Request, respHeader http.Header, body []byte, respCode int) *Message {
	var bodySnapshot []byte

	getBody := func() (io.ReadCloser, error) {
		if len(bodySnapshot) != 0 {
			return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
		}

		save, newBody, err := drainBody(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body = newBody
		bodySnapshot = save

		return io.NopCloser(bytes.NewReader(bodySnapshot)), nil
	}

	return &Message{
		Method:        req.Method,
		Authority:     req.Host,
		URL:           req.URL,
		Header:        respHeader.Clone(),
		Body:          func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil },
		StatusCode:    respCode,
		RequestHeader: req.Header.Clone(),
		RequestBody:   getBody,
		IsRequest:     false,
		Context:       req.Context(),
	}
}

// Message represents the HTTP request or response data needed to construct
// and verify an HTTP message signature. For a response, request-related
// fields supply data used by component identifiers with the ;req parameter.
// Not every field is necessarily covered by the signature.
// Message data must remain stable after it is prepared for signing or
// verification, apart from headers added by signing. A Message must not be
// copied after its first use.
type Message struct {
	// Context is passed to key resolution and Accept-Signature nonce generation.
	Context context.Context //nolint: containedctx

	// Method is the associated HTTP request method.
	Method string

	// Authority is the authority (host and optional port) of the request.
	Authority string

	// URL is the associated HTTP request URL.
	URL *url.URL

	// Header contains the headers of the request or response being processed.
	// The signer may update this map with signatures and a Content-Digest.
	Header http.Header

	// Body opens the body of the request or response being processed.
	Body func() (io.ReadCloser, error)

	// RequestHeader contains the associated request headers for a response.
	RequestHeader http.Header

	// RequestBody opens the associated request body for response ;req components.
	RequestBody func() (io.ReadCloser, error)

	// StatusCode is the HTTP response status code (unused for requests).
	StatusCode int

	// IsRequest distinguishes requests from responses for canonicalization.
	IsRequest bool

	queryOnce   sync.Once
	queryValues url.Values
}

// queryParams parses the associated request query at most once per Message.
func (m *Message) queryParams() url.Values {
	m.queryOnce.Do(func() {
		m.queryValues = m.URL.Query()
	})

	return m.queryValues
}

func (m *Message) addSignature(label string, signature []byte, signatureInput httpsfv.InnerList) (http.Header, error) {
	// check to see if there are already signature/signature-input headers
	// if there are we want to store the current (case-sensitive) name of the header,
	// and we want to parse out the current values, so we can append our new signature
	var (
		signatureHeaderDict *httpsfv.Dictionary
		inputHeaderDict     *httpsfv.Dictionary
		err                 error
	)

	if signatureHeader := m.Header.Values(headerSignature); len(signatureHeader) != 0 {
		signatureHeaderDict, err = httpsfv.UnmarshalDictionary(signatureHeader)
	} else {
		signatureHeaderDict = httpsfv.NewDictionary()
	}

	if err != nil {
		return nil, err
	}

	if inputHeader := m.Header.Values(headerSignatureInput); len(inputHeader) != 0 {
		inputHeaderDict, err = httpsfv.UnmarshalDictionary(inputHeader)
	} else {
		inputHeaderDict = httpsfv.NewDictionary()
	}

	if err != nil {
		return nil, err
	}

	label = createUniqueLabel(label, inputHeaderDict)

	signatureHeaderDict.Add(label, httpsfv.NewItem(signature))
	inputHeaderDict.Add(label, signatureInput)

	marshalledSignatureHeader, err := httpsfv.Marshal(signatureHeaderDict)
	if err != nil {
		return nil, err
	}

	marshalledInputHeader, err := httpsfv.Marshal(inputHeaderDict)
	if err != nil {
		return nil, err
	}

	m.Header.Set(headerSignature, marshalledSignatureHeader)
	m.Header.Set(headerSignatureInput, marshalledInputHeader)

	return m.Header, nil
}

func createUniqueLabel(label string, dict *httpsfv.Dictionary) string {
	uniqueLabel := label
	_, labelPresent := dict.Get(uniqueLabel)

	for count := 1; labelPresent; count++ {
		uniqueLabel = fmt.Sprintf("%s%d", label, count)
		_, labelPresent = dict.Get(uniqueLabel)
	}

	return uniqueLabel
}

func drainBody(body io.ReadCloser) ([]byte, io.ReadCloser, error) {
	if body == nil || body == http.NoBody {
		// No copying needed. Preserve the magic sentinel meaning of NoBody.
		return nil, http.NoBody, nil
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(body); err != nil {
		return nil, body, err
	}

	if err := body.Close(); err != nil {
		return nil, body, err
	}

	data := buf.Bytes()

	return data, io.NopCloser(bytes.NewReader(data)), nil
}
