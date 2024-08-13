package httpsig

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"

	"github.com/dunglas/httpsfv"
)

type contentDigester struct {
	// alg and algName are used to create message digest
	alg     crypto.Hash
	algName DigestAlgorithm

	// fromRequest is used only to verify message digest
	fromRequest bool
}

func (c contentDigester) update(msg *Message) error {
	if val := msg.Header.Get(headerContentDigest); len(val) != 0 {
		// header already present. skipping
		return nil
	}

	body, err := c.readBody(msg.Body)
	if err != nil {
		return err
	}

	dict := httpsfv.NewDictionary()

	var algs map[DigestAlgorithm]crypto.Hash

	if len(c.algName) != 0 {
		algs = map[DigestAlgorithm]crypto.Hash{c.algName: c.alg}
	} else {
		algs = supportedAlgs
	}

	for name, alg := range algs {
		md := alg.New()
		_, _ = md.Write(body)

		dict.Add(string(name), httpsfv.NewItem(md.Sum(nil)))
	}

	marshalled, err := httpsfv.Marshal(dict)
	if err != nil {
		return err
	}

	msg.Header.Set(headerContentDigest, marshalled)

	return nil
}

func (c contentDigester) verify(msg *Message) error {
	var (
		hdr     http.Header
		getBody func() (io.ReadCloser, error)
	)

	if c.fromRequest {
		hdr = msg.RequestHeader
		getBody = msg.RequestBody
	} else {
		hdr = msg.Header
		getBody = msg.Body
	}

	dict, err := httpsfv.UnmarshalDictionary(hdr.Values(headerContentDigest))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedData, err)
	}

	body, err := c.readBody(getBody)
	if err != nil {
		return err
	}

	var hasVerified bool

	for _, algName := range dict.Names() {
		alg, known := supportedAlgs[DigestAlgorithm(algName)]
		if !known {
			continue
		}

		item, _ := dict.Get(algName)
		hasVerified = true

		md := alg.New()
		md.Write(body)
		res := md.Sum(nil)

		valueItem, ok := item.(httpsfv.Item)
		if !ok {
			return fmt.Errorf("%w: invalid content-digest value", ErrMalformedData)
		}

		value, ok := valueItem.Value.([]byte)
		if !ok {
			return fmt.Errorf("%w: invalid content-digest value", ErrMalformedData)
		}

		if subtle.ConstantTimeCompare(res, value) != 1 {
			return ErrContentDigestMismatch
		}
	}

	if !hasVerified {
		return ErrNoApplicableDigestFound
	}

	return nil
}

func (c contentDigester) readBody(getBody func() (io.ReadCloser, error)) ([]byte, error) {
	body, err := getBody()
	if err != nil {
		return nil, err
	}

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	_ = body.Close()

	return data, nil
}
