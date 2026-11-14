package proxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/client/event"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/client"
	"github.com/fatedier/frp/pkg/util/xlog"
)

type mockCloseProxy struct {
	Proxy
	closed   atomic.Bool
	runCount atomic.Int32
}

func (p *mockCloseProxy) Run() error {
	p.runCount.Add(1)
	return nil
}

func (p *mockCloseProxy) Close() {
	p.closed.Store(true)
}

func (p *mockCloseProxy) InWorkConn(conn net.Conn, _ *msg.StartWorkConn) {
	_ = conn.Close()
}

// TestWrapperHealthCheckFailureClosesProxy_CANON069 verifies that when health check
// fails, the wrapper closes the running proxy (pw.pxy.Close()) before transitioning
// to ProxyPhaseCheckFailed.
func TestWrapperHealthCheckFailureClosesProxy_CANON069(t *testing.T) {
	require := require.New(t)

	mockPxy := &mockCloseProxy{}
	closedProxyMsgCount := atomic.Int32{}

	pw := &Wrapper{
		WorkingStatus: WorkingStatus{
			Name:  "test-pxy",
			Type:  "tcp",
			Phase: ProxyPhaseRunning,
		},
		pxy:            mockPxy,
		xl:             xlog.New(),
		closeCh:        make(chan struct{}),
		healthNotifyCh: make(chan struct{}, 1),
		handler: func(payload any) error {
			if _, ok := payload.(*event.CloseProxyPayload); ok {
				closedProxyMsgCount.Add(1)
			}
			return nil
		},
	}

	// Mark health as failed (non-zero)
	atomic.StoreUint32(&pw.health, 1)

	// Start checkWorker in goroutine
	go pw.checkWorker()
	t.Cleanup(pw.Stop)

	// Trigger health notification
	pw.healthNotifyCh <- struct{}{}

	// Verify that mockPxy.Close() is called and phase becomes ProxyPhaseCheckFailed
	require.Eventually(func() bool {
		pw.mu.RLock()
		phase := pw.Phase
		pw.mu.RUnlock()
		return phase == ProxyPhaseCheckFailed && mockPxy.closed.Load()
	}, 2*time.Second, 10*time.Millisecond)

	require.True(mockPxy.closed.Load(), "proxy must be closed on health check failure")
	require.GreaterOrEqual(closedProxyMsgCount.Load(), int32(1), "CloseProxy message must be sent to frps")
}

// TestWrapperCheckWorkerStopRace_CANON068 verifies that checkWorker does not send
// StartProxyPayload after Stop() has closed the proxy.
func TestWrapperCheckWorkerStopRace_CANON068(t *testing.T) {
	require := require.New(t)

	for i := range 20 {
		startMsgCount := atomic.Int32{}
		closeMsgCount := atomic.Int32{}
		var eventsMu sync.Mutex
		var eventSequence []string

		cfg := &v1.TCPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{
				Name: "race-proxy",
				Type: "tcp",
			},
		}

		mockPxy := &mockCloseProxy{}
		pw := &Wrapper{
			WorkingStatus: WorkingStatus{
				Name:  "race-proxy",
				Type:  "tcp",
				Phase: ProxyPhaseNew,
				Cfg:   cfg,
			},
			pxy:            mockPxy,
			xl:             xlog.New(),
			closeCh:        make(chan struct{}),
			healthNotifyCh: make(chan struct{}, 1),
			handler: func(payload any) error {
				eventsMu.Lock()
				defer eventsMu.Unlock()
				switch payload.(type) {
				case *event.StartProxyPayload:
					startMsgCount.Add(1)
					eventSequence = append(eventSequence, "start")
				case *event.CloseProxyPayload:
					closeMsgCount.Add(1)
					eventSequence = append(eventSequence, "close")
				}
				return nil
			},
		}

		// Run checkWorker and Stop concurrently
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			go pw.checkWorker()
			time.Sleep(time.Duration(i%5) * time.Millisecond)
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration((i+2)%5) * time.Millisecond)
			pw.Stop()
		}()

		wg.Wait()
		pw.Stop() // ensure stopped

		// Verify event sequence: if "close" occurred, "start" must NOT appear after "close"
		eventsMu.Lock()
		seq := make([]string, len(eventSequence))
		copy(seq, eventSequence)
		eventsMu.Unlock()

		sawClose := false
		for _, evt := range seq {
			if evt == "close" {
				sawClose = true
			} else if evt == "start" && sawClose {
				t.Fatalf("StartProxy was dispatched AFTER CloseProxy! sequence: %v", seq)
			}
		}

		pw.mu.RLock()
		phase := pw.Phase
		pw.mu.RUnlock()
		require.Equal(ProxyPhaseClosed, phase)
	}
}

var registerTrackingPluginOnce sync.Once

type trackingClosePlugin struct {
	name       string
	closed     atomic.Bool
	closeCount atomic.Int32
}

func (p *trackingClosePlugin) Name() string                                       { return p.name }
func (p *trackingClosePlugin) Handle(_ context.Context, _ *plugin.ConnectionInfo) {}
func (p *trackingClosePlugin) Close() error {
	p.closed.Store(true)
	p.closeCount.Add(1)
	return nil
}

// TestBaseProxyRunClosesExistingPlugin_CANON069 verifies that BaseProxy.Run() closes
// any existing proxyPlugin before creating a new one on health check recovery.
func TestBaseProxyRunClosesExistingPlugin_CANON069(t *testing.T) {
	require := require.New(t)

	const pluginType = "tracking-close-test-plugin"
	registerTrackingPluginOnce.Do(func() {
		plugin.Register(pluginType, func(pluginCtx plugin.PluginContext, _ v1.ClientPluginOptions) (plugin.Plugin, error) {
			return &trackingClosePlugin{name: pluginCtx.Name}, nil
		})
	})

	cfg := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "plugin-leak-test",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				Plugin: v1.TypedClientPluginOptions{
					Type: pluginType,
				},
			},
		},
	}

	base := &BaseProxy{
		baseCfg:   &cfg.ProxyBaseConfig,
		clientCfg: &v1.ClientCommonConfig{},
		xl:        xlog.New(),
		ctx:       context.Background(),
	}

	// First Run() initializes plugin1
	err := base.Run()
	require.NoError(err)
	p1 := base.getPlugin()
	require.NotNil(p1)
	plugin1, ok := p1.(*trackingClosePlugin)
	require.True(ok)
	require.False(plugin1.closed.Load(), "plugin1 should not be closed initially")
	require.Equal(int32(0), plugin1.closeCount.Load())

	// Second Run() should close plugin1 and create plugin2 without leaking
	err = base.Run()
	require.NoError(err)
	p2 := base.getPlugin()
	require.NotNil(p2)
	plugin2, ok := p2.(*trackingClosePlugin)
	require.True(ok)
	require.NotSame(plugin1, plugin2, "new plugin instance should be created")

	// Verify plugin1 was actually closed when BaseProxy.Run() executed the second time
	require.True(plugin1.closed.Load(), "existing plugin1 must be closed when BaseProxy.Run() re-executes")
	require.Equal(int32(1), plugin1.closeCount.Load(), "plugin1 Close() must be called exactly once")
	require.False(plugin2.closed.Load(), "newly created plugin2 should not be closed yet")

	// Close() cleans up plugin2
	base.Close()
	require.Nil(base.getPlugin())
	require.True(plugin2.closed.Load(), "active plugin2 must be closed when base.Close() is called")
	require.Equal(int32(1), plugin2.closeCount.Load())
}
