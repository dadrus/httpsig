package httpsig

import (
	"strings"

	"github.com/dunglas/httpsfv"
)

type component struct {
	key   *componentIdentifier
	value []string
}

type componentList []component

func (s componentList) marshal() (string, error) {
	var builder strings.Builder

	for _, item := range s {
		marshalledKey, err := httpsfv.Marshal(item.key)
		if err != nil {
			return "", err
		}

		_, err = builder.WriteString(marshalledKey + ": " + strings.Join(item.value, ", ") + "\n")
		if err != nil {
			return "", err
		}
	}

	return strings.TrimRight(builder.String(), "\n"), nil
}
