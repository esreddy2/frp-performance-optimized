package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFullReturnsNonEmptySemverString(t *testing.T) {
	v := Full()
	require.NotEmpty(t, v)
	require.Regexp(t, `^\d+\.\d+\.\d+`, v)
}
