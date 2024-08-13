package httpsig

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
	"github.com/felixge/httpsnoop"
)

type HandlerOption func(*handler)

type Logger interface {
	Logf(ctx context.Context, msg string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Logf(_ context.Context, _ string, _ ...any) {}

func WithLogger(logger Logger) HandlerOption {
	return func(h *handler) {
		if logger != nil {
			h.l = logger
		}
	}
}

func WithErrorCode(code int) HandlerOption {
	return func(h *handler) {
		h.ec = code
	}
}

func WithSignedResponses(signer *signer) HandlerOption {
	return func(h *handler) {
		if signer != nil {
			h.s = append(h.s, signer)
		}
	}
}

func WithSignedResponseNegotiation(kr KeyResolver) HandlerOption {
	return func(h *handler) {
		if kr != nil {
			h.kr = kr
		}
	}
}

type handler struct {
	v  Verifier
	s  compositeSigner
	kr KeyResolver
	l  Logger
	ec int
}

func (h *handler) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if err := h.v.Verify(MessageFromRequest(req)); err != nil {
			var errNoApplicable *NoApplicableSignatureError

			if errors.As(err, &errNoApplicable) {
				h.l.Logf(req.Context(), "No applicable http signature present.")

				errNoApplicable.Negotiate(rw.Header())
			} else {
				h.l.Logf(req.Context(), "Failed verifying http signature: %v.", err)
			}

			rw.WriteHeader(h.ec)

			return
		}

		signer, done := h.signerFor(req)
		if done {
			rw.WriteHeader(h.ec)

			return
		}

		next.ServeHTTP(newResponseWriterWrapper(h.l, signer, rw, req), req)
	})
}

func (h *handler) signerFor(req *http.Request) (Signer, bool) {
	if h.kr == nil {
		return h.s, false
	}

	sigReqs, err := getSignatureRequirements(req.Header.Values(headerAcceptSignature))
	if err != nil {
		h.l.Logf(req.Context(), "Failed negotiating http signature for response: %v.", err)

		return nil, true
	}

	signer := make(compositeSigner, 0, len(sigReqs))

	for label, sigReq := range sigReqs {
		key, err := h.kr.ResolveKey(req.Context(), sigReq.keyID)
		if err != nil {
			h.l.Logf(req.Context(), "Failed resolving key for http signature response: %v.", err)

			return nil, true
		}

		if key.Algorithm != sigReq.alg {
			h.l.Logf(req.Context(), "Requested key %s does not support requested algorithm %s.",
				sigReq.keyID, sigReq.alg)

			return nil, true
		}

		opts := []SignerOption{
			WithTag(sigReq.tag),
			WithLabel(label),
			//withComponents(sigReq.identifiers),
			WithNonce(NonceGetterFunc(func(_ context.Context) (string, error) {
				return sigReq.nonce, nil
			})),
		}

		if !sigReq.expires {
			opts = append(opts, WithTTL(0))
		}

		sgnr, err := NewSigner(key, opts...)
		if err != nil {
			h.l.Logf(req.Context(), "Failed resolving key for http signature response: %v.", err)

			return nil, true
		}

		signer = append(signer, sgnr)
	}

	return signer, false
}

func getSignatureRequirements(values []string) (map[string]*signatureRequirements, error) {
	inputDict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
	}

	sigRefs := make(map[string]*signatureRequirements, len(inputDict.Names()))

	for _, label := range inputDict.Names() {
		var sr signatureRequirements

		m, _ := inputDict.Get(label)

		sigReqs, ok := m.(httpsfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("%w: unexpected signature requirements format", ErrMalformedData)
		}

		if err = sr.fromInnerList(sigReqs); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedData, err)
		}

		sigRefs[label] = &sr
	}

	return sigRefs, nil
}

func NewVerifierMiddleware(verifier Verifier, opts ...HandlerOption) func(http.Handler) http.Handler {
	hdl := &handler{
		v:  verifier,
		l:  noopLogger{},
		ec: http.StatusBadRequest,
	}

	for _, opt := range opts {
		opt(hdl)
	}

	if hdl.s != nil && hdl.kr != nil {
		panic("WithSignedResponses and WithSignedResponseNegotiation are mutually exclusive")
	}

	return func(next http.Handler) http.Handler {
		return hdl.wrap(next)
	}
}

type responseWriterAdapter struct {
	s   Signer
	l   Logger
	rw  http.ResponseWriter
	req *http.Request

	msgSignedOrInProgress bool
}

func newResponseWriterWrapper(
	logger Logger,
	signer Signer,
	rw http.ResponseWriter,
	req *http.Request,
) http.ResponseWriter {
	if signer == nil {
		return rw
	}

	rwa := &responseWriterAdapter{
		l:   logger,
		s:   signer,
		req: req,
		rw:  rw,
	}

	return httpsnoop.Wrap(
		rw,
		httpsnoop.Hooks{
			Flush:       rwa.flush,
			Write:       rwa.write,
			WriteHeader: rwa.writeHeader,
		},
	)
}

func (a *responseWriterAdapter) sign(rw http.ResponseWriter, req *http.Request, data []byte, code int) error {
	hdr, err := a.s.Sign(MessageForResponse(req, rw.Header(), data, code))
	if err != nil {
		return err
	}

	if len(hdr) == 0 {
		return nil
	}

	rw.Header().Set("Signature-Input", hdr.Get("Signature-Input"))
	rw.Header().Set("Signature", hdr.Get("Signature"))
	rw.Header().Add("Vary", "Signature-Input")
	rw.Header().Add("Vary", "Signature")

	return nil
}

func (a *responseWriterAdapter) flush(flush httpsnoop.FlushFunc) httpsnoop.FlushFunc {
	return func() {
		if a.msgSignedOrInProgress {
			flush()

			return
		}

		a.msgSignedOrInProgress = true

		if err := a.sign(a.rw, a.req, nil, http.StatusOK); err != nil {
			a.l.Logf(a.req.Context(), "Failed signing http response: %v", err)
			a.rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		flush()
	}
}

func (a *responseWriterAdapter) write(write httpsnoop.WriteFunc) httpsnoop.WriteFunc {
	return func(data []byte) (int, error) {
		if a.msgSignedOrInProgress {
			return write(data)
		}

		a.msgSignedOrInProgress = true

		if err := a.sign(a.rw, a.req, data, http.StatusOK); err != nil {
			a.l.Logf(a.req.Context(), "Failed signing http response: %v", err)

			return 0, err
		}

		return write(data)
	}
}

func (a *responseWriterAdapter) writeHeader(writeHeader httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
	return func(code int) {
		if a.msgSignedOrInProgress {
			writeHeader(code)

			return
		}

		a.msgSignedOrInProgress = true

		if err := a.sign(a.rw, a.req, nil, code); err != nil {
			a.l.Logf(a.req.Context(), "Failed signing http response: %v", err)
			writeHeader(http.StatusInternalServerError)

			return
		}

		writeHeader(code)
	}
}

type compositeSigner []Signer

func (c compositeSigner) Sign(msg *Message) (http.Header, error) {
	var (
		hdr http.Header
		err error
	)

	for _, signer := range c {
		hdr, err = signer.Sign(msg)
		if err != nil {
			return nil, err
		}
	}

	return hdr, nil
}
