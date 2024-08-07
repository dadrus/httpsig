package httpsig

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

type AcceptedSignatureOption func(*AcceptedSignatureBuilder) error

func WithExpectedKey(key Key) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		if len(key.KeyID) != 0 {
			asb.keyID = key.KeyID
		}

		if len(key.Algorithm) != 0 {
			asb.keyAlgorithm = key.Algorithm
		}

		return nil
	}
}

func WithExpectedNonce(ng NonceGetter) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		if ng != nil {
			asb.nonceGetter = ng
		}

		return nil
	}
}

func WithExpectedLabel(label string) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		asb.label = label

		return nil
	}
}

func WithExpectedComponents(identifiers ...string) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		var err error

		asb.identifiers, err = toComponentIdentifiers(identifiers)

		for _, identifier := range asb.identifiers {
			if identifier.Value == "content-digest" {
				asb.wantContentDigest = true

				break
			}
		}

		return err
	}
}

func WithContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		if len(prefs) != 0 {
			asb.cdAlgPrefs = prefs
		}

		return nil
	}
}

func WithExpectedTag(tag string) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		if len(tag) != 0 {
			asb.tag = tag
		}

		return nil
	}
}

func WithExpectedCreatedTimestamp(flag bool) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		asb.addCreatedTS = flag

		return nil
	}
}

func WithExpectedExpiresTimestamp(flag bool) AcceptedSignatureOption {
	return func(asb *AcceptedSignatureBuilder) error {
		asb.addExpiresTS = flag

		return nil
	}
}

type AlgorithmPreference struct {
	Algorithm  DigestAlgorithm
	Preference int
}

func (p AlgorithmPreference) String() string {
	return fmt.Sprintf("%s=%d", p.Algorithm, p.Preference)
}

type AcceptedSignatureBuilder struct {
	keyAlgorithm      SignatureAlgorithm
	keyID             string
	nonceGetter       NonceGetter
	label             string
	identifiers       []*componentIdentifier
	cdAlgPrefs        []AlgorithmPreference
	tag               string
	addCreatedTS      bool
	addExpiresTS      bool
	wantContentDigest bool
}

func (asb *AcceptedSignatureBuilder) Build(ctx context.Context, header http.Header) error {
	nonce, err := asb.nonceGetter.GetNonce(ctx)
	if err != nil {
		return err
	}

	sigReqs := newSignatureRequirements(
		asb.addCreatedTS,
		asb.addExpiresTS,
		asb.tag,
		nonce,
		asb.keyID,
		asb.keyAlgorithm,
		asb.identifiers)

	dict := httpsfv.NewDictionary()
	dict.Add(asb.label, sigReqs.InnerList)

	result, err := httpsfv.Marshal(dict)
	if err != nil {
		return err
	}

	header.Add(headerAcceptSignature, result)

	if asb.wantContentDigest {
		for _, pref := range asb.cdAlgPrefs {
			header.Add(headerWantContentDigest, pref.String())
		}
	}

	return nil
}

func NewAcceptedSignature(opts ...AcceptedSignatureOption) (*AcceptedSignatureBuilder, error) {
	asb := &AcceptedSignatureBuilder{
		addCreatedTS: true,
		addExpiresTS: true,
		nonceGetter:  nonceGetter{},
		label:        "sig",
		cdAlgPrefs: []AlgorithmPreference{
			{Algorithm: Sha256, Preference: 5},
			{Algorithm: Sha512, Preference: 10},
		},
	}

	for _, opt := range opts {
		if err := opt(asb); err != nil {
			return nil, err
		}
	}

	return asb, nil
}
