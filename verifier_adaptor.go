package httpsig

import "context"

type messageVerifierAdaptor struct {
	verifier MessageVerifier
}

func (v *messageVerifierAdaptor) verify(ctx context.Context, payload, signature []byte) error {
	return v.verifier.VerifyMessage(ctx, payload, signature)
}
