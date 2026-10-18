package httpsig

import "strings"

type component struct {
	key   *componentIdentifier
	value []string
}

func (c component) canonicalValue() string {
	return strings.Join(c.value, ", ")
}
