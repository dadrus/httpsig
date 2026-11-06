package httpsig

import "context"

type messageSignerAdaptor struct {
	signer MessageSigner
}

func (s *messageSignerAdaptor) sign(ctx context.Context, payload []byte) ([]byte, error) {
	return s.signer.SignMessage(ctx, payload)
}
