package framework

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/test/e2e/pkg/port"
)

func TestMockServersUDSPortTracking(t *testing.T) {
	pa := port.NewAllocator(40000, 40050, 1, 0)
	servers := NewMockServers(pa)
	defer servers.Close()

	udsPort := servers.UDSPort()
	require.Greater(t, udsPort, 0, "mock UDS port must be allocated")

	params := servers.GetTemplateParams()
	require.Equal(t, udsPort, params[UDSEchoServerPort], "UDSEchoServerPort param must match allocated UDS port")

	// Verify that releasing returns it to allocator
	pa.Release(udsPort)
}
