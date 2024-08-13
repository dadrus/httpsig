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
