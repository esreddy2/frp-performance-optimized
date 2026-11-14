package prometheus

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func gatherMetricValue(t *testing.T, fqName string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != fqName {
			continue
		}
		for _, m := range mf.GetMetric() {
			matched := true
			for k, v := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched {
				if m.GetGauge() != nil {
					return m.GetGauge().GetValue()
				}
				if m.GetCounter() != nil {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	t.Fatalf("metric %s with labels %v not found", fqName, labels)
	return 0
}

func metricExists(t *testing.T, fqName string, labels map[string]string) bool {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != fqName {
			continue
		}
		for _, m := range mf.GetMetric() {
			matched := true
			for k, v := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func TestPrometheusServerMetricsUpdatesCountersAndGauges(t *testing.T) {
	require := require.New(t)

	baseClients := gatherMetricValue(t, "frp_server_client_counts", nil)
	ServerMetrics.NewClient()
	require.InDelta(baseClients+1, gatherMetricValue(t, "frp_server_client_counts", nil), 1e-9)
	ServerMetrics.CloseClient()
	require.InDelta(baseClients, gatherMetricValue(t, "frp_server_client_counts", nil), 1e-9)

	ServerMetrics.NewProxy("pxy-prom", "tcp", "user1", "cid1")
	require.InDelta(1, gatherMetricValue(t, "frp_server_proxy_counts", map[string]string{"type": "tcp"}), 1e-9)
	require.InDelta(1, gatherMetricValue(t, "frp_server_proxy_counts_detailed", map[string]string{"type": "tcp", "name": "pxy-prom"}), 1e-9)

	ServerMetrics.OpenConnection("pxy-prom", "tcp")
	require.InDelta(1, gatherMetricValue(t, "frp_server_connection_counts", map[string]string{"name": "pxy-prom", "type": "tcp"}), 1e-9)

	ServerMetrics.AddTrafficIn("pxy-prom", "tcp", 512)
	ServerMetrics.AddTrafficOut("pxy-prom", "tcp", 1024)
	require.InDelta(512, gatherMetricValue(t, "frp_server_traffic_in", map[string]string{"name": "pxy-prom", "type": "tcp"}), 1e-9)
	require.InDelta(1024, gatherMetricValue(t, "frp_server_traffic_out", map[string]string{"name": "pxy-prom", "type": "tcp"}), 1e-9)

	ServerMetrics.CloseConnection("pxy-prom", "tcp")
	require.InDelta(0, gatherMetricValue(t, "frp_server_connection_counts", map[string]string{"name": "pxy-prom", "type": "tcp"}), 1e-9)

	ServerMetrics.CloseProxy("pxy-prom", "tcp")
	require.InDelta(0, gatherMetricValue(t, "frp_server_proxy_counts", map[string]string{"type": "tcp"}), 1e-9)
	require.False(metricExists(t, "frp_server_proxy_counts_detailed", map[string]string{"type": "tcp", "name": "pxy-prom"}))
	require.False(metricExists(t, "frp_server_connection_counts", map[string]string{"name": "pxy-prom", "type": "tcp"}))
	require.False(metricExists(t, "frp_server_traffic_in", map[string]string{"name": "pxy-prom", "type": "tcp"}))
	require.False(metricExists(t, "frp_server_traffic_out", map[string]string{"name": "pxy-prom", "type": "tcp"}))
}
