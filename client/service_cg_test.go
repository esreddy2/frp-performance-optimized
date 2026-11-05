package client

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// CG-001: metricsServer listener is released on initial login failure.
func TestRunStopsMetricsServerOnInitialLoginFailure(t *testing.T) {
	port := getFreeTCPPort(t)
	agg := source.NewAggregator(source.NewConfigSource())

	svr, err := NewService(ServiceOptions{
		Common: &v1.ClientCommonConfig{
			LoginFailExit: new(true),
			MetricsServer: v1.MetricsServerConfig{
				Addr: "127.0.0.1",
				Port: port,
			},
		},
		ConfigSourceAggregator: agg,
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			return &failingConnector{err: errors.New("login boom")}
		},
	})
	require.NoError(t, err)

	err = svr.Run(context.Background())
	require.Error(t, err)
	require.Nil(t, svr.metricsServer)

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	_ = ln.Close()
}

// CG-002: re-running Run() on a closed service does not attempt login.
func TestServiceRerunAfterCloseDoesNotLogin(t *testing.T) {
	var attempts atomic.Int64
	agg := source.NewAggregator(source.NewConfigSource())

	svr, err := NewService(ServiceOptions{
		Common:                 &v1.ClientCommonConfig{LoginFailExit: new(true)},
		ConfigSourceAggregator: agg,
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			attempts.Add(1)
			return &failingConnector{err: net.ErrClosed}
		},
	})
	require.NoError(t, err)

	svr.Close()
	for range 2 {
		runErr := svr.Run(context.Background())
		require.ErrorIs(t, runErr, context.Canceled)
	}
	require.Zero(t, attempts.Load())
}

// CG-002: closing during an in-flight login prevents a subsequent Run().
func TestServiceCloseDuringInFlightLoginPreventsRerun(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int64

	svr, address := newLifecycleTestService(t, func(ctx context.Context, _ *v1.ClientCommonConfig) Connector {
		attempts.Add(1)
		close(entered)
		<-resume
		return &failingConnector{err: ctx.Err()}
	})
	defer close(resume)

	ctx := t.Context()

	runDone := make(chan struct{})
	go func() { _ = svr.Run(ctx); close(runDone) }()

	waitLifecycleSignal(t, entered)
	svr.Close()
	resume <- struct{}{}
	waitLifecycleSignal(t, runDone)

	rerunErr := svr.Run(context.Background())
	require.ErrorIs(t, rerunErr, context.Canceled)
	require.Equal(t, int64(1), attempts.Load())
	assertLifecycleAdminPort(t, address, true)
}

// CG-003: panic from OnFirstLoginSuccess propagates out of Run.
func TestServiceOnFirstLoginSuccessPanicPropagates(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	trackedConn := &trackingConn{Conn: clientConn}
	connector := &testConnector{conn: trackedConn}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	serverErr := make(chan error, 1)
	go func() {
		rw := msg.NewV1ReadWriter(serverConn)
		var login msg.Login
		if err := rw.ReadMsgInto(&login); err != nil {
			serverErr <- err
			return
		}
		serverErr <- rw.WriteMsg(&msg.LoginResp{RunID: "panic-run"})
		_ = serverConn.Close()
	}()

	svr, err := NewService(ServiceOptions{
		Common:                 &v1.ClientCommonConfig{},
		ConfigSourceAggregator: source.NewAggregator(source.NewConfigSource()),
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			return connector
		},
		OnFirstLoginSuccess: func(string) error {
			panic("boom")
		},
	})
	require.NoError(t, err)

	runDone := make(chan any, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				runDone <- r
				return
			}
			runDone <- nil
		}()
		_ = svr.Run(context.Background())
	}()

	select {
	case v := <-runDone:
		require.NotNil(t, v, "expected panic from OnFirstLoginSuccess")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for panic propagation")
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(5 * time.Second):
	}
}

// CG-004: GracefulClose against Run's deferred stop with a real cancel.
func TestGracefulCloseIntegrationWithRunCancel(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	trackedConn := &trackingConn{Conn: clientConn}
	connector := &testConnector{conn: trackedConn}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		rw := msg.NewV1ReadWriter(serverConn)
		var login msg.Login
		if err := rw.ReadMsgInto(&login); err != nil {
			serverErr <- err
			return
		}
		if err := rw.WriteMsg(&msg.LoginResp{RunID: "gc-run"}); err != nil {
			serverErr <- err
			return
		}
		<-ctx.Done()
		serverErr <- nil
	}()

	svr, err := NewService(ServiceOptions{
		Common:                 &v1.ClientCommonConfig{},
		ConfigSourceAggregator: source.NewAggregator(source.NewConfigSource()),
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			return connector
		},
	})
	require.NoError(t, err)

	runDone := make(chan struct{})
	var runErr error
	go func() { runErr = svr.Run(ctx); close(runDone) }()

	require.Eventually(t, func() bool {
		svr.ctlMu.RLock()
		defer svr.ctlMu.RUnlock()
		return svr.ctl != nil
	}, 5*time.Second, time.Millisecond)

	const d = 100 * time.Millisecond
	gcDone := make(chan struct{})
	go func() { svr.GracefulClose(d); close(gcDone) }()

	select {
	case <-gcDone:
	case <-time.After(20 * time.Millisecond):
		t.Fatal("GracefulClose blocked while Run owns teardown")
	}

	select {
	case <-runDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not exit after GracefulClose")
	}
	cancel()
	require.NoError(t, runErr)

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
}

// CG-005: UpdateConfigSource concurrent with GracefulClose/stop.
func TestUpdateConfigSourceConcurrentWithStop(t *testing.T) {
	svr := &Service{
		configSource: source.NewConfigSource(),
		aggregator:   source.NewAggregator(source.NewConfigSource()),
		reloadCommon: &v1.ClientCommonConfig{},
	}

	stopDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			time.Sleep(5 * time.Millisecond)
			svr.Close()
			close(stopDone)
		}()
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopDone:
					return
				default:
				}
				_ = svr.UpdateConfigSource(&v1.ClientCommonConfig{}, nil, nil)
			}
		}()
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent UpdateConfigSource/stop did not finish")
	}
}

// CG-006: vnet controller cleanup on shutdown/initial failure.
func TestServiceVnetControllerCleanupOnFailure(t *testing.T) {
	port := getFreeTCPPort(t)
	agg := source.NewAggregator(source.NewConfigSource())

	svr, err := NewService(ServiceOptions{
		Common: &v1.ClientCommonConfig{
			LoginFailExit: new(true),
			VirtualNet:    v1.VirtualNetConfig{Address: "10.0.0.1/24"},
			WebServer: v1.WebServerConfig{
				Addr: "127.0.0.1",
				Port: port,
			},
		},
		ConfigSourceAggregator: agg,
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			return &failingConnector{err: errors.New("login boom")}
		},
	})
	require.NoError(t, err)

	err = svr.Run(context.Background())
	require.Error(t, err)
	require.Nil(t, svr.vnetController)

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	require.NoError(t, err)
	_ = ln.Close()
}

// CG-007: deterministic cancellation/hook timing using channels.
func TestServiceOnFirstLoginSuccessHookAllowsConcurrentCancellation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	trackedConn := &trackingConn{Conn: clientConn}
	connector := &testConnector{conn: trackedConn}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		rw := msg.NewV1ReadWriter(serverConn)
		var login msg.Login
		if err := rw.ReadMsgInto(&login); err != nil {
			serverErr <- err
			return
		}
		if err := rw.WriteMsg(&msg.LoginResp{RunID: "race-run"}); err != nil {
			serverErr <- err
			return
		}
		<-ctx.Done()
		serverErr <- nil
	}()

	hookStarted := make(chan struct{})
	hookRelease := make(chan struct{})
	var callbacks atomic.Int32

	svr, err := NewService(ServiceOptions{
		Common:                 &v1.ClientCommonConfig{},
		ConfigSourceAggregator: source.NewAggregator(source.NewConfigSource()),
		ConnectorCreator: func(context.Context, *v1.ClientCommonConfig) Connector {
			return connector
		},
		OnFirstLoginSuccess: func(runID string) error {
			callbacks.Add(1)
			close(hookStarted)
			<-hookRelease
			return nil
		},
	})
	require.NoError(t, err)

	runDone := make(chan struct{})
	var runErr error
	go func() { runErr = svr.Run(ctx); close(runDone) }()

	select {
	case <-hookStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for hook to start")
	}

	cancel()
	close(hookRelease)

	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Run to exit")
	}
	require.NoError(t, runErr)
	require.Equal(t, int32(1), callbacks.Load())

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
}
