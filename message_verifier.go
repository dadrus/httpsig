package httpsig

//go:generate mockery --name messageVerifier --structname MessageVerifierMock --inpackage --testonly

type messageVerifier interface {
	verify(msg *Message) error
}

type noopMessageVerifier struct{}

func (noopMessageVerifier) verify(_ *Message) error { return nil }

type compositeMessageVerifier []messageVerifier

func (v compositeMessageVerifier) verify(msg *Message) error {
	for _, mv := range v {
		if err := mv.verify(msg); err != nil {
			return err
		}
	}

	return nil
}

func createMessageVerifier(identifiers []*componentIdentifier) messageVerifier {
	var cmv compositeMessageVerifier

	for _, id := range identifiers {
		if id.Value == "content-digest" {
			_, fromReq := id.Params.Get("req")

			cmv = append(cmv, contentDigester{fromRequest: fromReq})
		}
	}

	if len(cmv) == 0 {
		return noopMessageVerifier{}
	}

	return cmv
}
