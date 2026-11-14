package request

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRequestHTTPBoundedTimeout(t *testing.T) {
	// Normal server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok response"))
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, _ := strconv.Atoi(portStr)

	// Send normal request
	req := New().HTTP().Addr(host).Port(port)
	resp, err := req.Do()
	require.NoError(t, err)
	require.Equal(t, 200, resp.Code)
	require.Equal(t, []byte("ok response"), resp.Content)

	// Stalled server that never replies
	stalledTs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer stalledTs.Close()

	stalledHost, stalledPortStr, err := net.SplitHostPort(stalledTs.Listener.Addr().String())
	require.NoError(t, err)
	stalledPort, _ := strconv.Atoi(stalledPortStr)

	// Request with short timeout (200ms)
	reqTimeout := New().HTTP().Addr(stalledHost).Port(stalledPort).Timeout(200 * time.Millisecond)
	start := time.Now()
	_, err = reqTimeout.Do()
	elapsed := time.Since(start)

	require.Error(t, err, "Request should fail due to timeout")
	require.Less(t, elapsed, 2*time.Second, "Request should not hang for server sleep duration")
}
