package aggregate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/server/metrics"
)

type recordingMetrics struct {
	clients     int
	proxies     int
	connections int
	trafficIn   int64
	trafficOut  int64
}

func (r *recordingMetrics) NewClient()                                   { r.clients++ }
func (r *recordingMetrics) CloseClient()                                 { r.clients-- }
func (r *recordingMetrics) NewProxy(_, _, _, _ string)                   { r.proxies++ }
func (r *recordingMetrics) CloseProxy(_, _ string)                       { r.proxies-- }
func (r *recordingMetrics) OpenConnection(_, _ string)                   { r.connections++ }
func (r *recordingMetrics) CloseConnection(_, _ string)                  { r.connections-- }
func (r *recordingMetrics) AddTrafficIn(_, _ string, trafficBytes int64) { r.trafficIn += trafficBytes }
func (r *recordingMetrics) AddTrafficOut(_, _ string, trafficBytes int64) {
	r.trafficOut += trafficBytes
}

func TestAggregateServerMetricsFanOut(t *testing.T) {
	require := require.New(t)

	orig := sm.ms
	t.Cleanup(func() {
		sm.ms = orig
	})
	sm.ms = nil

	r1 := &recordingMetrics{}
	r2 := &recordingMetrics{}
	sm.Add(r1)
	sm.Add(r2)
	EnableMem()
	EnablePrometheus()

	metrics.Server.NewClient()
	metrics.Server.NewProxy("web", "http", "alice", "cid-1")
	metrics.Server.OpenConnection("web", "http")
	metrics.Server.AddTrafficIn("web", "http", 1024)
	metrics.Server.AddTrafficOut("web", "http", 2048)

	for _, r := range []*recordingMetrics{r1, r2} {
		require.Equal(1, r.clients)
		require.Equal(1, r.proxies)
		require.Equal(1, r.connections)
		require.Equal(int64(1024), r.trafficIn)
		require.Equal(int64(2048), r.trafficOut)
	}

	metrics.Server.CloseConnection("web", "http")
	metrics.Server.CloseProxy("web", "http")
	metrics.Server.CloseClient()

	for _, r := range []*recordingMetrics{r1, r2} {
		require.Equal(0, r.clients)
		require.Equal(0, r.proxies)
		require.Equal(0, r.connections)
	}
}
