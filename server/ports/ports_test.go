package ports

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/fatedier/frp/pkg/config/types"
)

func TestManagerUsesClockForPortTimestamps(t *testing.T) {
	require := require.New(t)

	port := freeTCPPort(t)
	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	pm := newManagerWithClock("tcp", "127.0.0.1", []types.PortsRange{{Single: port}}, clk)

	realPort, err := pm.Acquire("proxy", port)
	require.NoError(err)
	require.Equal(port, realPort)
	require.Equal(start, pm.usedPorts[port].UpdateTime)

	releasedAt := start.Add(time.Minute)
	clk.SetTime(releasedAt)
	pm.Release(port)

	require.Equal(releasedAt, pm.reservedPorts["proxy"].UpdateTime)
}

func TestManagerCleanReservedPortsWorkerUsesClockTicker(t *testing.T) {
	require := require.New(t)

	port := freeTCPPort(t)
	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	pm := newManagerWithClock("tcp", "127.0.0.1", []types.PortsRange{{Single: port}}, clk)

	realPort, err := pm.Acquire("proxy", port)
	require.NoError(err)
	require.Equal(port, realPort)
	pm.Release(port)
	require.True(pm.hasReservedPort("proxy"))

	require.Eventually(clk.HasWaiters, time.Second, time.Millisecond)
	clk.Step(MaxPortReservedDuration + CleanReservedPortsInterval + time.Minute)

	require.Eventually(func() bool {
		return !pm.hasReservedPort("proxy")
	}, time.Second, time.Millisecond)
}

func (pm *Manager) hasReservedPort(name string) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, ok := pm.reservedPorts[name]
	return ok
}

func freePort(t *testing.T, network string) int {
	t.Helper()

	if network == "udp" {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	return freePort(t, "tcp")
}

func TestManagerReservedPortDoesNotStealAllocatedPort(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			require := require.New(t)

			p1 := freePort(t, network)
			p2 := freePort(t, network)
			for p1 == p2 {
				p2 = freePort(t, network)
			}
			pm := NewManager(network, "127.0.0.1", []types.PortsRange{{Single: p1}, {Single: p2}})
			defer pm.Close()

			// proxy-a acquires p1 and then releases it (p1 becomes reserved for proxy-a)
			got1, err := pm.Acquire("proxy-a", p1)
			require.NoError(err)
			require.Equal(p1, got1)
			pm.Release(p1)

			// proxy-b explicitly acquires p1 before binding OS socket
			gotB, err := pm.Acquire("proxy-b", p1)
			require.NoError(err)
			require.Equal(p1, gotB)

			// proxy-a now requests a dynamic port (0): must NOT steal p1 from proxy-b, must get p2
			gotA, err := pm.Acquire("proxy-a", 0)
			require.NoError(err)
			require.Equal(p2, gotA)
			require.Equal("proxy-b", pm.usedPorts[p1].ProxyName)
			require.Equal("proxy-a", pm.usedPorts[p2].ProxyName)

			// When p2 is also held, proxy-c requesting 0 gets ErrNoAvailablePort
			_, err = pm.Acquire("proxy-c", 0)
			require.ErrorIs(err, ErrNoAvailablePort)

			// Once both are released, proxy-a requesting 0 reuses its newly reserved port p2
			pm.Release(p1)
			pm.Release(p2)
			reused, err := pm.Acquire("proxy-a", 0)
			require.NoError(err)
			require.Equal(p2, reused)
		})
	}
}

func TestManagerAcquireErrorsAndUDPSupport(t *testing.T) {
	require := require.New(t)

	p1 := freeTCPPort(t)
	disallowedPort := freeTCPPort(t)
	if disallowedPort == p1 {
		disallowedPort++
	}

	// Test range configuration and nil clock fallback
	pm := newManagerWithClock("tcp", "127.0.0.1", []types.PortsRange{{Start: p1, End: p1}}, nil)
	defer pm.Close()
	pm.Close() // idempotent Close

	// 1. ErrPortNotAllowed when requesting port outside allowed range
	_, err := pm.Acquire("p-not-allowed", disallowedPort)
	require.ErrorIs(err, ErrPortNotAllowed)

	// 2. ErrPortUnAvailable when OS socket is already bound on p1
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	require.NoError(err)
	busyPort := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	pmBusy := NewManager("tcp", "127.0.0.1", []types.PortsRange{{Single: busyPort}})
	defer pmBusy.Close()
	_, err = pmBusy.Acquire("p-busy", busyPort)
	require.ErrorIs(err, ErrPortUnAvailable)
	_, err = pmBusy.Acquire("p-busy-random", 0)
	require.ErrorIs(err, ErrNoAvailablePort)

	// 3. ErrPortAlreadyUsed when port is already acquired by another proxy
	got, err := pm.Acquire("p1", p1)
	require.NoError(err)
	require.Equal(p1, got)
	_, err = pm.Acquire("p2", p1)
	require.ErrorIs(err, ErrPortAlreadyUsed)
	_, err = pm.Acquire("p3", 0)
	require.ErrorIs(err, ErrNoAvailablePort)

	// 4. UDP Manager acquire and release
	udpPM := NewManager("udp", "127.0.0.1", []types.PortsRange{{Single: p1}})
	defer udpPM.Close()
	udpPort, err := udpPM.Acquire("udp-p1", p1)
	require.NoError(err)
	require.Equal(p1, udpPort)
	udpPM.Release(udpPort)
}

func TestManagerAcquireDoesNotAbortAfterFiveTries(t *testing.T) {
	require := require.New(t)

	// Bind 6 real listeners so 6 ports are busy
	listeners := make([]net.Listener, 0, 6)
	ranges := make([]types.PortsRange, 0, 7)
	for range 6 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(err)
		listeners = append(listeners, ln)
		port := ln.Addr().(*net.TCPAddr).Port
		ranges = append(ranges, types.PortsRange{Single: port})
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	// Add 1 available port at the end
	freeP := freeTCPPort(t)
	ranges = append(ranges, types.PortsRange{Single: freeP})

	pm := NewManager("tcp", "127.0.0.1", ranges)
	defer pm.Close()

	// Dynamic acquire must check past the first 5 busy ports and allocate freeP
	got, err := pm.Acquire("p-more-than-5", 0)
	require.NoError(err)
	require.Equal(freeP, got)
}

func TestManagerReservedPortsUserIsolation(t *testing.T) {
	require := require.New(t)

	p1 := freeTCPPort(t)
	p2 := freeTCPPort(t)
	for p1 == p2 {
		p2 = freeTCPPort(t)
	}

	pm := NewManager("tcp", "127.0.0.1", []types.PortsRange{{Single: p1}, {Single: p2}})
	defer pm.Close()

	// Alice acquires p1 and releases it (reserved for alice:app)
	got, err := pm.Acquire("alice:app", p1)
	require.NoError(err)
	require.Equal(p1, got)
	pm.Release(p1)

	// Bob acquires dynamic port for bob:app -> must NOT get Alice's reserved port p1
	bobGot, err := pm.Acquire("bob:app", 0)
	require.NoError(err)
	require.Equal(p2, bobGot)

	// Alice acquires dynamic port for alice:app -> gets her reserved port p1
	aliceGot, err := pm.Acquire("alice:app", 0)
	require.NoError(err)
	require.Equal(p1, aliceGot)
}
