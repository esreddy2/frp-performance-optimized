// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	pkgerr "github.com/fatedier/frp/pkg/errors"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/proxy"
	"github.com/fatedier/frp/server/registry"
	"github.com/fatedier/frp/server/visitor"
)

type cgTempErr struct{}

func (cgTempErr) Error() string   { return "temporary accept error" }
func (cgTempErr) Temporary() bool { return true }

type cgTempListener struct {
	mu      sync.Mutex
	accepts []func() (net.Conn, error)
	idx     int
}

func (l *cgTempListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.idx < len(l.accepts) {
		fn := l.accepts[l.idx]
		l.idx++
		return fn()
	}
	return nil, net.ErrClosed
}

func (l *cgTempListener) Close() error { return nil }

func (l *cgTempListener) Addr() net.Addr { return lifecycleTestAddr("temp") }

// CG-014: HandleListener retries on temporary Accept errors and exits on a
// non-temporary error.
func TestHandleListenerTemporaryAcceptError(t *testing.T) {
	calls := 0
	ln := &cgTempListener{accepts: []func() (net.Conn, error){
		func() (net.Conn, error) { calls++; return nil, cgTempErr{} },
		func() (net.Conn, error) { calls++; return nil, net.ErrClosed },
	}}
	svr := &Service{}
	svr.HandleListener(ln, true)
	require.Equal(t, 2, calls)
}

type cgCloseCounter struct {
	closeCount atomic.Int64
}

func (c *cgCloseCounter) Close() error {
	c.closeCount.Add(1)
	return nil
}

// CG-015: a failed Login with a mux session closes that session.
func TestHandleConnectionFailedLoginWithMuxSessionClosesSession(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	session := &cgCloseCounter{}
	go func() {
		rw := msg.NewV1ReadWriter(clientConn)
		_ = rw.WriteMsg(&msg.Login{RunID: "some-run", Timestamp: 1, PrivilegeKey: "wrong"})
		_ = clientConn.Close()
	}()

	svr := newControlTestService(t)
	svr.handleConnection(context.Background(), serverConn, true, session)
	require.Equal(t, int64(1), session.closeCount.Load())
}

// CG-016: repeated and concurrent Run calls are serialized by the started flag.
func TestServiceRepeatedAndConcurrentRun(t *testing.T) {
	svr, listener, _ := newLifecycleTestService(t, false)
	t.Cleanup(func() { _ = svr.Close() })

	require.NoError(t, svr.Close())
	for range 2 {
		done := make(chan struct{})
		go func() { svr.Run(context.Background()); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return for closed service")
		}
	}
	require.Zero(t, listener.accepts.Load())

	svr2, _, _ := newLifecycleTestService(t, false)
	t.Cleanup(func() { _ = svr2.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runDone := make(chan struct{})
	go func() { svr2.Run(ctx); close(runDone) }()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		svr2.lifecycleMu.Lock()
		started := svr2.started
		svr2.lifecycleMu.Unlock()
		if started {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	secondDone := make(chan struct{})
	go func() { svr2.Run(context.Background()); close(secondDone) }()
	select {
	case <-secondDone:
	case <-time.After(2 * time.Second):
		t.Fatal("second Run did not return immediately")
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first Run did not return")
	}
}

// CG-017: CloseControl returns false for a pending (not yet activated) control.
func TestServiceCloseControlReturnsFalseForPendingControl(t *testing.T) {
	manager := NewControlManager(registry.NewClientRegistry())
	service := &Service{ctlManager: manager}

	metrics := newCountingServerMetrics()
	ctl, _ := newLifecycleTestControl(t, "pending-run", "client", metrics)
	require.NoError(t, manager.Add(ctl))

	require.False(t, service.CloseControl("pending-run"))
}

type cgTrackingConn struct {
	net.Conn
	mu               sync.Mutex
	lastReadDeadline time.Time
}

func (c *cgTrackingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.lastReadDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *cgTrackingConn) last() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastReadDeadline
}

func TestAcceptConnectionClearsReadDeadlineOnFailureCG018(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	tracking := &cgTrackingConn{Conn: serverConn}
	_ = clientConn.Close()

	_, err := (&Service{}).acceptConnection(context.Background(), tracking)
	require.Error(t, err)
	require.True(t, tracking.last().IsZero(), "read deadline not cleared on failure")
}

// CG-019: RegisterWorkConn pool-full tracking and close races do not panic.
func TestRegisterWorkConnPoolFullTracking(t *testing.T) {
	manager := NewControlManager(registry.NewClientRegistry())
	ctl, _ := newLifecycleTestControl(t, "pool-full", "client", newCountingServerMetrics())
	mustAddAndActivate(t, manager, ctl)
	require.True(t, ctl.Start())

	capacity := cap(ctl.workConnCh)
	workConns := make([]*proxy.WorkConn, 0, capacity)
	for range capacity {
		conn := newCloseRecordingConn(t)
		wc := proxy.NewWorkConn(conn.msgConn())
		require.NoError(t, manager.RegisterWorkConn(ctl, wc))
		workConns = append(workConns, wc)
	}
	require.Len(t, ctl.workConns, capacity)

	extraConn := newCloseRecordingConn(t)
	extraWorkConn := proxy.NewWorkConn(extraConn.msgConn())
	err := manager.RegisterWorkConn(ctl, extraWorkConn)
	require.ErrorContains(t, err, "work connection pool is full")
	require.Len(t, ctl.workConns, capacity)

	require.NoError(t, workConns[0].Close())
	require.Eventually(t, func() bool {
		ctl.mu.Lock()
		defer ctl.mu.Unlock()
		_, ok := ctl.workConns[workConns[0]]
		return !ok
	}, time.Second, 10*time.Millisecond)

	require.NoError(t, ctl.Close())
	waitForControlDone(t, ctl)
}

func TestRegisterWorkConnCloseRaceNoPanic(t *testing.T) {
	manager := NewControlManager(registry.NewClientRegistry())
	ctl, _ := newLifecycleTestControl(t, "send-closed", "client", newCountingServerMetrics())
	mustAddAndActivate(t, manager, ctl)
	require.True(t, ctl.Start())

	var wg sync.WaitGroup
	wg.Go(func() {
		time.Sleep(10 * time.Millisecond)
		_ = ctl.Close()
	})
	for range 8 {
		wg.Go(func() {
			defer func() { _ = recover() }()
			for range 25 {
				conn := newCloseRecordingConn(t)
				wc := proxy.NewWorkConn(conn.msgConn())
				if err := manager.RegisterWorkConn(ctl, wc); err == nil {
					_ = wc.Close()
				}
			}
		})
	}
	wg.Wait()
	waitForControlDone(t, ctl)
}

// CG-020: max_ports_per_client accounting stays consistent under concurrency.
func TestMaxPortsPerClientConcurrency(t *testing.T) {
	portMgr := ports.NewManager("tcp", "127.0.0.1", nil)
	t.Cleanup(portMgr.Close)

	rc := &controller.ResourceController{
		TCPPortManager: portMgr,
		VisitorManager: visitor.NewManager(),
	}
	cfg := &v1.ServerConfig{MaxPortsPerClient: 1}

	conn := newDeadlineReadConn()
	msgConn := msg.NewConn(conn, msg.NewV1ReadWriter(conn))
	ctl, err := NewControl(context.Background(), &SessionContext{
		RC:            rc,
		PxyManager:    proxy.NewManager(),
		PluginManager: plugin.NewManager(),
		AuthVerifier:  auth.AlwaysPassVerifier,
		Conn:          msgConn,
		LoginMsg: &msg.Login{
			RunID:     "ports-run",
			ClientID:  "client",
			PoolCount: 0,
		},
		ServerCfg: cfg,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctl.Close() })

	manager := NewControlManager(registry.NewClientRegistry())
	mustAddAndActivate(t, manager, ctl)
	require.True(t, ctl.Start())

	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := ctl.RegisterProxy(&msg.NewProxy{
				ProxyName:  "proxy-" + strconv.Itoa(i),
				ProxyType:  "tcp",
				RemotePort: 0,
			}, plugin.UserInfo{}, "attempt")
			if err == nil {
				successes.Add(1)
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, int64(1), successes.Load())

	_ = ctl.Close()
	waitForControlDone(t, ctl)
}

// CG-021: worker exit closes doneCh.
func TestControlWorkerPanicRecoveryClosesDoneCh(t *testing.T) {
	manager := NewControlManager(registry.NewClientRegistry())
	ctl, _ := newLifecycleTestControl(t, "worker-done", "client", newCountingServerMetrics())
	mustAddAndActivate(t, manager, ctl)
	require.True(t, ctl.Start())

	require.NoError(t, ctl.Close())
	waitForControlDone(t, ctl)
	select {
	case <-ctl.doneCh:
	default:
		t.Fatal("doneCh not closed after worker exit")
	}
}

// CG-027: GetWorkConn returns ErrCtlClosed without panicking after close.
func TestGetWorkConnPanicNilHandling(t *testing.T) {
	manager := NewControlManager(registry.NewClientRegistry())
	ctl, _ := newLifecycleTestControl(t, "get-work", "client", newCountingServerMetrics())
	mustAddAndActivate(t, manager, ctl)
	require.True(t, ctl.Start())

	require.NoError(t, ctl.Close())
	waitForControlDone(t, ctl)

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("GetWorkConn panicked: %v", r)
			}
		}()
		wc, err := ctl.GetWorkConn()
		require.Error(t, err)
		require.Nil(t, wc)
		require.ErrorIs(t, err, pkgerr.ErrCtlClosed)
	}()
}
