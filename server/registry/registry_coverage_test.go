package registry

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/fatedier/frp/pkg/proto/wire"
)

// CG-023: offline entries with a raw client ID are removed once disconnected
// for more than 24 hours.
func TestClientRegistryCleanupOfflineEntriesRemovesStaleRawClients(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	cr := newClientRegistryWithClock(clk)
	defer cr.Close()

	key, conflict := cr.Register("user", "raw-client", "run-1", "host", "1.0.0", "127.0.0.1", wire.ProtocolV1)
	require.False(conflict)

	cr.MarkOfflineByRunID("run-1")

	// Not yet stale: 1 hour elapsed.
	clk.SetTime(start.Add(time.Hour))
	cr.cleanupOfflineEntries()
	_, ok := cr.GetByKey(key)
	require.True(ok, "entry removed too early")

	// Stale: 25 hours elapsed.
	clk.SetTime(start.Add(25 * time.Hour))
	cr.cleanupOfflineEntries()
	_, ok = cr.GetByKey(key)
	require.False(ok, "stale offline entry not removed")
}

func TestClientRegistryCleanupOfflineEntriesKeepsOnlineAndNoRawClients(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	cr := newClientRegistryWithClock(clk)
	defer cr.Close()

	// Online entry with raw client ID must survive.
	onlineKey, _ := cr.Register("user", "online-client", "run-online", "host", "1.0.0", "127.0.0.1", wire.ProtocolV1)
	require.NotEmpty(onlineKey)
	clk.SetTime(start.Add(48 * time.Hour))
	cr.cleanupOfflineEntries()
	_, ok := cr.GetByKey(onlineKey)
	require.True(ok, "online entry removed")

	// Entry without raw client ID is deleted on disconnect, not via cleanup.
	noRawKey, _ := cr.Register("user", "", "run-noraw", "host", "1.0.0", "127.0.0.1", wire.ProtocolV1)
	require.NotEmpty(noRawKey)
	cr.MarkOfflineByRunID("run-noraw")
	_, ok = cr.GetByKey(noRawKey)
	require.False(ok, "no-raw entry should be deleted on disconnect")
}

// CG-024: Close is idempotent and stops the cleanup worker.
func TestClientRegistryCloseIsIdempotent(t *testing.T) {
	cr := NewClientRegistry()
	cr.Close()
	cr.Close() // must not panic or hang

	// Post-close operations are safe.
	_, conflict := cr.Register("user", "client", "run", "host", "1.0.0", "127.0.0.1", wire.ProtocolV1)
	if conflict {
		t.Fatal("unexpected conflict after close")
	}
	cr.MarkOfflineByRunID("run")
	cr.MarkOfflineByRunIDAndControlID("run", 1)
	_ = cr.List()
}

// CG-025: concurrent Register vs MarkOfflineByRunID* stress.
func TestClientRegistryRegisterVsMarkOfflineConcurrency(t *testing.T) {
	cr := NewClientRegistry()
	defer cr.Close()

	const goroutines = 32
	const iterations = 200

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range iterations {
				runID := "run-shared"
				key, conflict := cr.RegisterWithControlID(
					"user", "client-id", runID, "host", "1.0.0", "127.0.0.1", wire.ProtocolV1, uint64(id+1),
				)
				_ = key
				_ = conflict

				if i%2 == 0 {
					cr.MarkOfflineByRunID(runID)
				} else {
					cr.MarkOfflineByRunIDAndControlID(runID, uint64(id+1))
				}
				_ = cr.List()
				_, _ = cr.GetByKey("user.client-id")
			}
		}(g)
	}
	wg.Wait()
}
