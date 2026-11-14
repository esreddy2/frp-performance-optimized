package ssh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewTunnelClientAndClose(t *testing.T) {
	tc := NewTunnelClient("127.0.0.1:8080", "127.0.0.1:2222", "test-command")
	require.NotNil(t, tc)
	require.Equal(t, "127.0.0.1:8080", tc.localAddr)
	require.Equal(t, "127.0.0.1:2222", tc.sshServer)
	require.Equal(t, "test-command", tc.commands)

	// Close when nil connections/channel should not panic
	require.NotPanics(t, func() {
		tc.Close()
	})
}
