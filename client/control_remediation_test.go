package client

import (
	"errors"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	visitorPlugin "github.com/fatedier/frp/pkg/plugin/visitor"
)

type deadlineSpyConn struct {
	net.Conn
	mu               sync.Mutex
	lastReadDeadline time.Time
	readErr          error
	closed           bool
}

func (c *deadlineSpyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.lastReadDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineSpyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.mu.Lock()
		c.readErr = err
		c.mu.Unlock()
	}
	return n, err
}

func (c *deadlineSpyConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Conn.Close()
}

type stalledServerConnector struct {
	mu        sync.Mutex
	conns     []net.Conn
	spyConn   *deadlineSpyConn
	handshake atomic.Int32
}

func (c *stalledServerConnector) Open() error {
	return nil
}

func (c *stalledServerConnector) Connect() (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	spy := &deadlineSpyConn{Conn: clientConn}

	c.mu.Lock()
	c.spyConn = spy
	c.conns = append(c.conns, clientConn, serverConn)
	c.mu.Unlock()

	// Goroutine simulates server reading NewWorkConn, then stalling (never sending StartWorkConn)
	go func() {
		defer serverConn.Close()
		var newWorkConn msg.NewWorkConn
		_ = msg.ReadMsgInto(serverConn, &newWorkConn)
		c.handshake.Add(1)
		// Stalls here without sending StartWorkConn until closed
		buf := make([]byte, 1)
		_, _ = serverConn.Read(buf)
	}()

	return spy, nil
}

func (c *stalledServerConnector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.conns {
		_ = conn.Close()
	}
	return nil
}

// TestControlWorkConnReadDeadline_CANON063 verifies that workConn.ReadMsgInto aborts
// with a deadline / timeout error when a peer stalls on sending StartWorkConn, preventing
// indefinite goroutine hangs.
func TestControlWorkConnReadDeadline_CANON063(t *testing.T) {
	require := require.New(t)

	// 1. Direct unit verification: msg.ReadMsgInto aborts with timeout when read deadline expires
	pipeClient, pipeServer := net.Pipe()
	t.Cleanup(func() {
		_ = pipeClient.Close()
		_ = pipeServer.Close()
	})
	_ = pipeClient.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var directStartMsg msg.StartWorkConn
	directErr := msg.ReadMsgInto(pipeClient, &directStartMsg)
	require.Error(directErr)
	var directNetErr net.Error
	require.True(errors.As(directErr, &directNetErr) && directNetErr.Timeout(),
		"direct ReadMsgInto should fail with deadline timeout: %v", directErr)

	// 2. Control integration verification: handleReqWorkConn aborts on read deadline
	origTimeout := workConnReadTimeout
	workConnReadTimeout = 80 * time.Millisecond
	defer func() { workConnReadTimeout = origTimeout }()

	ctl, _, _ := newCGTestControl(t, nil)
	stalledConn := &stalledServerConnector{}
	t.Cleanup(func() { _ = stalledConn.Close() })

	ctl.sessionCtx.Connector = newMessageConnector(stalledConn, "")

	startTime := time.Now()
	doneCh := make(chan struct{})
	go func() {
		ctl.handleReqWorkConn(&msg.ReqWorkConn{})
		close(doneCh)
	}()

	select {
	case <-doneCh:
		elapsed := time.Since(startTime)
		require.GreaterOrEqual(elapsed, 70*time.Millisecond, "should wait for deadline before aborting")
		require.Less(elapsed, 2*time.Second, "should abort promptly on deadline without hanging indefinitely")
	case <-time.After(3 * time.Second):
		t.Fatal("handleReqWorkConn did not abort on read deadline")
	}

	// Verify that SetReadDeadline was called with a future deadline
	stalledConn.mu.Lock()
	spy := stalledConn.spyConn
	stalledConn.mu.Unlock()
	require.NotNil(spy)

	spy.mu.Lock()
	lastDeadline := spy.lastReadDeadline
	readErr := spy.readErr
	closed := spy.closed
	spy.mu.Unlock()

	require.True(lastDeadline.After(startTime), "SetReadDeadline should have been set with future deadline")
	require.Error(readErr)
	var netErr net.Error
	require.True(errors.As(readErr, &netErr) && netErr.Timeout(), "read error should be a timeout: %v", readErr)
	require.True(closed, "stalled connection should be closed after deadline error")

	// Verify the connection is untracked
	ctl.workConnsMu.Lock()
	tracked := len(ctl.workConns)
	ctl.workConnsMu.Unlock()
	require.Equal(0, tracked, "work connection should be untracked after aborting")
}

// TestControlWorkConnShutdownDeadlockPrevention_CANON063 verifies that in-flight
// work connections are tracked and closed during ctl.closeSession() / ctl.GracefulClose(),
// preventing WaitAsync() from deadlocking indefinitely.
func TestControlWorkConnShutdownDeadlockPrevention_CANON063(t *testing.T) {
	require := require.New(t)

	ctl, _, _ := newCGTestControl(t, nil)
	stalledConn := &stalledServerConnector{}
	t.Cleanup(func() { _ = stalledConn.Close() })

	ctl.sessionCtx.Connector = newMessageConnector(stalledConn, "")

	// Trigger handleReqWorkConn asynchronously
	ctl.msgDispatcher.RegisterAsyncHandler(&msg.ReqWorkConn{}, ctl.handleReqWorkConn)
	go ctl.handleReqWorkConn(&msg.ReqWorkConn{})

	// Wait for the work connection to be established and stalled on read
	require.Eventually(func() bool {
		return stalledConn.handshake.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	// Verify that the workConn is tracked in ctl.workConns
	ctl.workConnsMu.Lock()
	trackedCount := len(ctl.workConns)
	ctl.workConnsMu.Unlock()
	require.Equal(1, trackedCount, "work connection should be tracked while in-flight")

	// GracefulClose must complete promptly because closeSession() closes tracked workConns
	doneCh := make(chan struct{})
	go func() {
		_ = ctl.GracefulClose(10 * time.Millisecond)
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// Success: shutdown completed without deadlocking
	case <-time.After(3 * time.Second):
		t.Fatal("GracefulClose deadlocked on stalled work connection")
	}

	// Verify all tracked workConns are cleared
	ctl.workConnsMu.Lock()
	remaining := len(ctl.workConns)
	ctl.workConnsMu.Unlock()
	require.Equal(0, remaining)
}

// Mock structures to trace execution order of proxy manager vs visitor manager
type orderTestProxyConfig struct {
	*v1.TCPProxyConfig
}

type orderDummyProxy struct{}

func (p *orderDummyProxy) Run() error                              { return nil }
func (p *orderDummyProxy) InWorkConn(net.Conn, *msg.StartWorkConn) {}
func (p *orderDummyProxy) SetInWorkConnCallback(func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool) {
}
func (p *orderDummyProxy) Close() {}

var (
	orderMutex        sync.Mutex
	orderExecutionLog []string
	orderRegistryOnce sync.Once
)

func recordOrderStep(step string) {
	orderMutex.Lock()
	defer orderMutex.Unlock()
	orderExecutionLog = append(orderExecutionLog, step)
}

func getOrderSteps() []string {
	orderMutex.Lock()
	defer orderMutex.Unlock()
	copied := make([]string, len(orderExecutionLog))
	copy(copied, orderExecutionLog)
	return copied
}

func clearOrderSteps() {
	orderMutex.Lock()
	defer orderMutex.Unlock()
	orderExecutionLog = nil
}

type orderTestVisitorPlugin struct{}

func (p *orderTestVisitorPlugin) Name() string { return "order-test-plugin" }
func (p *orderTestVisitorPlugin) Close() error { return nil }
func (p *orderTestVisitorPlugin) Start()       {}

func initOrderTestingRegistrations() {
	orderRegistryOnce.Do(func() {
		proxy.RegisterProxyFactory(reflect.TypeFor[*orderTestProxyConfig](), func(_ *proxy.BaseProxy, _ v1.ProxyConfigurer) proxy.Proxy {
			recordOrderStep("pm")
			return &orderDummyProxy{}
		})

		visitorPlugin.Register("order-test-plugin", func(_ visitorPlugin.PluginContext, _ v1.VisitorPluginOptions) (visitorPlugin.Plugin, error) {
			recordOrderStep("vm")
			return &orderTestVisitorPlugin{}, nil
		})
	})
}

// TestControlStandardizedLockOrdering_CANON071 verifies that Control.Run and
// Control.UpdateAllConfigurer both invoke pm.UpdateAll strictly before vm.UpdateAll in consistent order.
func TestControlStandardizedLockOrdering_CANON071(t *testing.T) {
	require := require.New(t)
	initOrderTestingRegistrations()

	ctl, _, _ := newCGTestControl(t, nil)
	t.Cleanup(func() { _ = ctl.GracefulClose(0) })

	proxyCfg := &orderTestProxyConfig{
		TCPProxyConfig: &v1.TCPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{
				Name: "order-test-proxy",
				Type: "tcp",
			},
		},
	}
	visitorCfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "order-test-visitor",
			Type:       "stcp",
			ServerName: "order-server",
			SecretKey:  "secret",
			Plugin: v1.TypedVisitorPluginOptions{
				Type: "order-test-plugin",
			},
		},
	}

	clearOrderSteps()

	// UpdateAllConfigurer must invoke pm.UpdateAll first, then vm.UpdateAll
	err := ctl.UpdateAllConfigurer(
		[]v1.ProxyConfigurer{proxyCfg},
		[]v1.VisitorConfigurer{visitorCfg},
	)
	require.NoError(err)

	steps := getOrderSteps()
	require.Equal([]string{"pm", "vm"}, steps, "UpdateAllConfigurer must execute pm.UpdateAll strictly before vm.UpdateAll")

	// Also verify Control.Run invokes pm before vm
	ctl2, _, _ := newCGTestControl(t, nil)
	t.Cleanup(func() { _ = ctl2.GracefulClose(0) })

	proxyCfg2 := &orderTestProxyConfig{
		TCPProxyConfig: &v1.TCPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{
				Name: "order-test-proxy-2",
				Type: "tcp",
			},
		},
	}
	visitorCfg2 := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "order-test-visitor-2",
			Type:       "stcp",
			ServerName: "order-server",
			SecretKey:  "secret",
			Plugin: v1.TypedVisitorPluginOptions{
				Type: "order-test-plugin",
			},
		},
	}

	clearOrderSteps()
	ctl2.Run(
		[]v1.ProxyConfigurer{proxyCfg2},
		[]v1.VisitorConfigurer{visitorCfg2},
	)

	stepsRun := getOrderSteps()
	require.Equal([]string{"pm", "vm"}, stepsRun, "Control.Run must execute pm.UpdateAll strictly before vm.UpdateAll")
}
