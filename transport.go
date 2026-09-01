package httpsig

import (
	"net/http"
)

// NewTransport returns a new client transport that wraps the provided transport with
// http message signing and verifying.
func NewTransport(inner http.RoundTripper, signer Signer) http.RoundTripper {
	return rt(func(req *http.Request) (*http.Response, error) {
		hdr, err := signer.Sign(MessageFromRequest(req))
		if err != nil {
			return nil, err
		}

		req.Header = hdr

		return inner.RoundTrip(req)
	})
}

type rt func(*http.Request) (*http.Response, error)

func (r rt) RoundTrip(req *http.Request) (*http.Response, error) { return r(req) }
