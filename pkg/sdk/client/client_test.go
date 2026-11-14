package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/client/http/model"
)

func TestSDKClientAllOperations(t *testing.T) {
	require := require.New(t)

	var (
		gotAuth       atomic.Value
		gotStrictMode atomic.Value
		gotConfigPut  atomic.Value
		stopCalled    atomic.Bool
		statusMode    atomic.Int32
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))

		mode := statusMode.Load()
		if mode == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if mode == 2 {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not-valid-json"))
			return
		}

		switch r.URL.Path {
		case "/api/status":
			resp := model.StatusResp{
				"tcp": {
					{Name: "ssh", Type: "tcp", Status: "running", LocalAddr: "127.0.0.1:22", RemoteAddr: "0.0.0.0:6000"},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/api/reload":
			gotStrictMode.Store(r.URL.Query().Get("strictConfig"))
			w.WriteHeader(http.StatusOK)
		case "/api/stop":
			stopCalled.Store(true)
			w.WriteHeader(http.StatusOK)
		case "/api/config":
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte("serverPort = 7000"))
			case http.MethodPut:
				b, _ := io.ReadAll(r.Body)
				gotConfigPut.Store(string(b))
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(err)
	port, err := strconv.Atoi(portStr)
	require.NoError(err)

	cli := New(host, port)
	cli.SetAuth("admin", "secret")

	ctx := context.Background()

	// 1. GetProxyStatus found and not found
	ps, err := cli.GetProxyStatus(ctx, "ssh")
	require.NoError(err)
	require.Equal("ssh", ps.Name)
	require.Equal("running", ps.Status)
	require.NotEmpty(gotAuth.Load())

	_, err = cli.GetProxyStatus(ctx, "missing")
	require.ErrorContains(err, "no proxy status found")

	// 2. GetAllProxyStatus
	all, err := cli.GetAllProxyStatus(ctx)
	require.NoError(err)
	require.Len(all["tcp"], 1)

	// 3. Reload (strictMode=false and strictMode=true)
	require.NoError(cli.Reload(ctx, false))
	require.Equal("", gotStrictMode.Load())
	require.NoError(cli.Reload(ctx, true))
	require.Equal("true", gotStrictMode.Load())

	// 4. GetConfig & UpdateConfig
	cfgStr, err := cli.GetConfig(ctx)
	require.NoError(err)
	require.Equal("serverPort = 7000", cfgStr)

	require.NoError(cli.UpdateConfig(ctx, "serverPort = 7001"))
	require.Equal("serverPort = 7001", gotConfigPut.Load())

	// 5. Stop
	require.NoError(cli.Stop(ctx))
	require.True(stopCalled.Load())

	// 6. Non-200 status code and invalid JSON handling
	statusMode.Store(1)
	_, err = cli.GetProxyStatus(ctx, "ssh")
	require.ErrorContains(err, "api status code [500]")
	_, err = cli.GetAllProxyStatus(ctx)
	require.ErrorContains(err, "api status code [500]")

	statusMode.Store(2)
	_, err = cli.GetProxyStatus(ctx, "ssh")
	require.ErrorContains(err, "unmarshal http response error")
	_, err = cli.GetAllProxyStatus(ctx)
	require.ErrorContains(err, "unmarshal http response error")
}
