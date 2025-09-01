package httpsig

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

type AcceptSignatureOption func(*AcceptSignatureBuilder) error

func WithExpectedKey(key Key) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.keyID = key.KeyID
		asb.keyAlgorithm = key.Algorithm

		return nil
	}
}

func WithExpectedNonce(ng NonceGetter) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		if ng != nil {
			asb.nonceGetter = ng
		}

		return nil
	}
}

func WithExpectedLabel(label string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		if len(label) != 0 {
			asb.label = label
		}

		return nil
	}
}

func WithExpectedComponents(identifiers ...string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		identifiers, err := toComponentIdentifiers(identifiers)
		if err != nil {
			return err
		}

		asb.setIdentifiers(identifiers)

		return nil
	}
}

func WithContentDigestAlgorithmPreferences(prefs ...AlgorithmPreference) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		if len(prefs) == 0 {
			return nil
		}

		algPrefs := make([]string, len(prefs))

		for i, pref := range prefs {
			if pref.Algorithm == "" {
				return fmt.Errorf("%w: digest algorithm preference requires a non-empty algorithm", ErrParameter)
			}

			algPrefs[i] = pref.String()
		}

		asb.cdAlgPrefs = algPrefs

		return nil
	}
}

func WithExpectedTag(tag string) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.tag = tag

		return nil
	}
}

func WithExpectedCreatedTimestamp(flag bool) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
		asb.addCreatedTS = flag

		return nil
	}
}

func WithExpectedExpiresTimestamp(flag bool) AcceptSignatureOption {
	return func(asb *AcceptSignatureBuilder) error {
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

type AcceptSignatureBuilder struct {
	keyAlgorithm      SignatureAlgorithm
	keyID             string
	nonceGetter       NonceGetter
	label             string
	identifiers       []*componentIdentifier
	cdAlgPrefs        []string
	tag               string
	addCreatedTS      bool
	addExpiresTS      bool
	wantContentDigest bool
}

func NewAcceptSignature(opts ...AcceptSignatureOption) (*AcceptSignatureBuilder, error) {
	asb := &AcceptSignatureBuilder{
		addCreatedTS: true,
		addExpiresTS: true,
		nonceGetter:  nonceGetter{},
		label:        "sig",
		cdAlgPrefs: []string{
			AlgorithmPreference{Algorithm: Sha256, Preference: 5}.String(),  //nolint: mnd
			AlgorithmPreference{Algorithm: Sha512, Preference: 10}.String(), //nolint: mnd
		},
	}

	for _, opt := range opts {
		if err := opt(asb); err != nil {
			return nil, err
		}
	}

	return asb, nil
}

func (asb *AcceptSignatureBuilder) Build(ctx context.Context, header http.Header) error {
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
			header.Add(headerWantContentDigest, pref)
		}
	}

	return nil
}

func (asb *AcceptSignatureBuilder) setIdentifiers(identifiers []*componentIdentifier) {
	asb.identifiers = identifiers

	for _, identifier := range asb.identifiers {
		if identifier.Value == componentIdentifierContentDigest {
			asb.wantContentDigest = true

			break
		}
	}
}
