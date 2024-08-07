package httpsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComponentListMarshal(t *testing.T) {
	t.Parallel()

	msg := &Message{Method: "GET", Authority: "foo.bar", IsRequest: true}

	ci, err := toComponentIdentifiers([]string{"@authority", "@method"})
	require.NoError(t, err)

	list := make(componentList, len(ci))

	for i, id := range ci {
		c, err := id.createComponent(msg)
		require.NoError(t, err)

		list[i] = c
	}

	res, err := list.marshal()
	require.NoError(t, err)

	assert.Equal(t, "\"@authority\": foo.bar\n\"@method\": GET", res)
}
