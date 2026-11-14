package port

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAllocatorZeroMod(t *testing.T) {
	// Must not panic on mod == 0 or negative values
	require.NotPanics(t, func() {
		pa := NewAllocator(20000, 20005, 0, 0)
		require.NotNil(t, pa)
		require.Equal(t, 6, pa.reserved.Len())
	})

	require.NotPanics(t, func() {
		pa := NewAllocator(20000, 20005, -2, -1)
		require.NotNil(t, pa)
		require.Equal(t, 6, pa.reserved.Len())
	})
}

func TestPortAllocatorRetryPruning(t *testing.T) {
	// Allocate a listener on a random free port to simulate an occupied port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()

	occupiedPort := l.Addr().(*net.TCPAddr).Port

	// Create allocator with ONLY the occupied port
	pa := NewAllocator(occupiedPort, occupiedPort, 1, 0)
	portName := GenName("test", WithRangePorts(occupiedPort, occupiedPort))

	// GetByName should attempt occupiedPort, fail, prune it, and return 0
	allocated := pa.GetByName(portName)
	require.Zero(t, allocated, "occupied port must not be allocated")

	// Ensure occupiedPort was pruned from reserved and marked used
	pa.mu.Lock()
	require.False(t, pa.reserved.Has(occupiedPort), "occupied port must be pruned from reserved")
	require.True(t, pa.used.Has(occupiedPort), "occupied port must be marked used")
	pa.mu.Unlock()

	// Now add a free port to the same allocator. Since occupiedPort was pruned,
	// the allocator must not be starved by the occupied port and must successfully allocate freePort.
	lFree, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	freePort := lFree.Addr().(*net.TCPAddr).Port
	_ = lFree.Close() // Release so it can be allocated

	pa.mu.Lock()
	pa.reserved.Insert(freePort)
	pa.mu.Unlock()

	minP := min(occupiedPort, freePort)
	maxP := max(occupiedPort, freePort)
	portName2 := GenName("test", WithRangePorts(minP, maxP))

	allocated2 := pa.GetByName(portName2)
	require.Equal(t, freePort, allocated2, "must allocate free port after occupied port was pruned")

	pa.mu.Lock()
	require.False(t, pa.reserved.Has(occupiedPort), "occupied port must remain pruned")
	require.False(t, pa.reserved.Has(freePort), "allocated port must be removed from reserved")
	require.True(t, pa.used.Has(occupiedPort), "occupied port must remain marked used")
	require.True(t, pa.used.Has(freePort), "free port must be marked used")
	pa.mu.Unlock()
}

func TestPortAllocatorRelease(t *testing.T) {
	pa := NewAllocator(30000, 30010, 1, 0)
	p := pa.Get()
	require.NotZero(t, p)

	pa.mu.Lock()
	require.True(t, pa.used.Has(p))
	require.False(t, pa.reserved.Has(p))
	pa.mu.Unlock()

	pa.Release(p)

	pa.mu.Lock()
	require.False(t, pa.used.Has(p))
	require.True(t, pa.reserved.Has(p))
	pa.mu.Unlock()
}

func TestConcurrentPortAllocation(t *testing.T) {
	const count = 10
	pa := NewAllocator(35000, 35050, 1, 0)

	var wg sync.WaitGroup
	ports := make([]int, count)
	for i := range count {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ports[idx] = pa.Get()
		}(i)
	}
	wg.Wait()

	seen := make(map[int]bool)
	for _, p := range ports {
		if p > 0 {
			require.False(t, seen[p], fmt.Sprintf("port %d allocated more than once", p))
			seen[p] = true
		}
	}
}
