package mem

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestServerMetricsUsesClockForProxyTimestamps(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	metrics := newServerMetricsWithClock(clk)

	metrics.NewProxy("proxy", "tcp", "user", "client-id")
	require.Equal(start, metrics.info.ProxyStatistics["proxy"].LastStartTime)

	closedAt := start.Add(time.Minute)
	clk.SetTime(closedAt)
	metrics.CloseProxy("proxy", "tcp")
	require.Equal(closedAt, metrics.info.ProxyStatistics["proxy"].LastCloseTime)

	stats := metrics.GetProxyByName("proxy")
	require.Equal(start.Format("01-02 15:04:05"), stats.LastStartTime)
	require.Equal(closedAt.Format("01-02 15:04:05"), stats.LastCloseTime)
	require.Equal(start.Unix(), stats.LastStartAt)
	require.Equal(closedAt.Unix(), stats.LastCloseAt)
}

func TestServerMetricsClearUselessInfoUsesClock(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start.Add(25 * time.Hour))
	metrics := newServerMetricsWithClock(clk)
	metrics.info.ProxyStatistics["proxy"] = &ProxyStatistics{
		Name:          "proxy",
		LastStartTime: start.Add(-time.Hour),
		LastCloseTime: start,
	}

	count, total := metrics.clearUselessInfo(24 * time.Hour)

	require.Equal(1, count)
	require.Equal(1, total)
	require.Empty(metrics.info.ProxyStatistics)
}

func TestServerMetricsClearOfflineProxiesPreservesLegacyTotal(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start.Add(time.Minute))
	metrics := newServerMetricsWithClock(clk)
	metrics.info.ProxyStatistics["offline"] = &ProxyStatistics{
		Name:          "offline",
		LastStartTime: start.Add(-time.Hour),
		LastCloseTime: start,
	}
	metrics.info.ProxyStatistics["online"] = &ProxyStatistics{
		Name:          "online",
		LastStartTime: start,
	}

	cleared, total := metrics.ClearOfflineProxies()

	require.Equal(1, cleared)
	require.Equal(2, total)
	require.False(metrics.hasProxyStatistics("offline"))
	require.True(metrics.hasProxyStatistics("online"))
}

func TestServerMetricsPruneOfflineProxiesReportsTotalStats(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start.Add(time.Minute))
	metrics := newServerMetricsWithClock(clk)
	metrics.info.ProxyStatistics["offline"] = &ProxyStatistics{
		Name:          "offline",
		LastStartTime: start.Add(-time.Hour),
		LastCloseTime: start,
	}
	metrics.info.ProxyStatistics["online"] = &ProxyStatistics{
		Name:          "online",
		LastStartTime: start,
	}
	metrics.info.ProxyStatistics["restarted"] = &ProxyStatistics{
		Name:          "restarted",
		LastStartTime: start.Add(30 * time.Second),
		LastCloseTime: start,
	}
	metrics.info.ProxyStatistics["same-time"] = &ProxyStatistics{
		Name:          "same-time",
		LastStartTime: start,
		LastCloseTime: start,
	}

	cleared, total := metrics.PruneOfflineProxies()

	require.Equal(1, cleared)
	require.Equal(4, total)
	require.False(metrics.hasProxyStatistics("offline"))
	require.True(metrics.hasProxyStatistics("online"))
	require.True(metrics.hasProxyStatistics("restarted"))
	require.True(metrics.hasProxyStatistics("same-time"))

	cleared, total = metrics.PruneOfflineProxies()
	require.Equal(0, cleared)
	require.Equal(3, total)
}

func TestServerMetricsRunUsesClockTicker(t *testing.T) {
	require := require.New(t)

	start := time.Date(2026, time.May, 8, 12, 30, 0, 0, time.UTC)
	clk := clocktesting.NewFakeClock(start)
	metrics := newServerMetricsWithClock(clk)
	metrics.info.ProxyStatistics["proxy"] = &ProxyStatistics{
		Name:          "proxy",
		LastStartTime: start.Add(-time.Hour),
		LastCloseTime: start,
	}

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		metrics.runUntil(stopCh)
	}()
	t.Cleanup(func() {
		close(stopCh)
		<-done
	})

	require.Eventually(clk.HasWaiters, time.Second, time.Millisecond)
	clk.Step(8 * 24 * time.Hour)

	require.Eventually(func() bool {
		return !metrics.hasProxyStatistics("proxy")
	}, time.Second, time.Millisecond)
}

func (m *serverMetrics) hasProxyStatistics(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.info.ProxyStatistics[name]
	return ok
}

func TestServerMetricsAllOperationsAndQueries(t *testing.T) {
	require := require.New(t)

	m := newServerMetricsWithClock(nil)

	m.NewClient()
	m.NewClient()
	m.CloseClient()

	m.NewProxy("ssh", "tcp", "alice", "cid-1")
	m.NewProxy("dns", "udp", "bob", "cid-2")
	m.OpenConnection("ssh", "tcp")
	m.OpenConnection("ssh", "tcp")
	m.CloseConnection("ssh", "tcp")
	m.AddTrafficIn("ssh", "tcp", 1024)
	m.AddTrafficOut("ssh", "tcp", 2048)

	srvStats := m.GetServer()
	require.Equal(int64(1), srvStats.ClientCounts)
	require.Equal(int64(1), srvStats.CurConns)
	require.Equal(int64(1024), srvStats.TotalTrafficIn)
	require.Equal(int64(2048), srvStats.TotalTrafficOut)
	require.Equal(int64(1), srvStats.ProxyTypeCounts["tcp"])
	require.Equal(int64(1), srvStats.ProxyTypeCounts["udp"])

	tcpProxies := m.GetProxiesByType("tcp")
	require.Len(tcpProxies, 1)
	require.Equal("ssh", tcpProxies[0].Name)
	require.Equal("alice", tcpProxies[0].User)
	require.Equal("cid-1", tcpProxies[0].ClientID)
	require.Equal(int64(1), tcpProxies[0].CurConns)

	byTypeAndName := m.GetProxiesByTypeAndName("tcp", "ssh")
	require.NotNil(byTypeAndName)
	require.Equal("ssh", byTypeAndName.Name)
	require.Nil(m.GetProxiesByTypeAndName("udp", "ssh"))

	traffic := m.GetProxyTraffic("ssh")
	require.NotNil(traffic)
	require.Equal("ssh", traffic.Name)
	require.Len(traffic.TrafficIn, ReserveDays)
	require.Len(traffic.TrafficOut, ReserveDays)
	require.Nil(m.GetProxyTraffic("nonexistent"))
}
