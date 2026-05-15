package httpsig

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonceCheckerFuncImplementsNonceChecker(t *testing.T) {
	t.Parallel()

	var checker NonceChecker = NonceCheckerFunc(func(_ context.Context, nonce NonceValue) error {
		assert.True(t, nonce.Present)
		assert.Equal(t, nonce.Value, "foo")

		return nil
	})

	err := checker.CheckNonce(context.Background(), NonceValue{Present: true, Value: "foo"})
	require.NoError(t, err)
}
