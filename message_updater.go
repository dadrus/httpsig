package httpsig

type messageUpdater interface {
	update(msg *Message) error
}

type noopMessageUpdater struct{}

func (noopMessageUpdater) update(_ *Message) error { return nil }

type compositeMessageUpdater []messageUpdater

func (v compositeMessageUpdater) update(msg *Message) error {
	for _, mv := range v {
		if err := mv.update(msg); err != nil {
			return err
		}
	}

	return nil
}

func createMessageUpdater(identifiers []*componentIdentifier) messageUpdater {
	var cmv compositeMessageUpdater

	for _, id := range identifiers {
		if id.Value == "content-digest" {
			if _, present := id.Params.Get("req"); !present {
				cmv = append(cmv, contentDigester{})
			}
		}
	}

	if len(cmv) == 0 {
		return noopMessageUpdater{}
	}

	return cmv
}
