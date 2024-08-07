package httpsig

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/dunglas/httpsfv"
)

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

// Message is a representation of an HTTP request or response, containing the values
// needed to construct or validate a signature.
type Message struct {
	Context       context.Context //nolint: containedctx
	Method        string
	Authority     string
	URL           *url.URL
	Header        http.Header
	Body          func() (io.ReadCloser, error)
	RequestHeader http.Header
	RequestBody   func() (io.ReadCloser, error)
	StatusCode    int
	IsRequest     bool
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
