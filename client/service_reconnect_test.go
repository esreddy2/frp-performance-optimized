package client

import (
	"fmt"
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
)

var (
	reconnectFactoryOnce   sync.Once
	currentHandoffCallback atomic.Pointer[func()]
)

type reconnectHandoffProxyConfig struct {
	*v1.TCPProxyConfig
}

type reconnectDummyProxy struct{}

func (p *reconnectDummyProxy) Run() error                              { return nil }
func (p *reconnectDummyProxy) InWorkConn(net.Conn, *msg.StartWorkConn) {}
func (p *reconnectDummyProxy) SetInWorkConnCallback(func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool) {
}
func (p *reconnectDummyProxy) Close() {}

func initReconnectProxyFactory() {
	reconnectFactoryOnce.Do(func() {
		proxy.RegisterProxyFactory(reflect.TypeFor[*reconnectHandoffProxyConfig](), func(_ *proxy.BaseProxy, _ v1.ProxyConfigurer) proxy.Proxy {
			if cb := currentHandoffCallback.Load(); cb != nil && *cb != nil {
				(*cb)()
			}
			return &reconnectDummyProxy{}
		})
	})
}

// TestServiceReconnectClosesOldControlBeforeRun_CANON067 verifies that when
// Service.loopLoginUntilSuccess reconnects, the old control instance is closed
// before ctl.Run(proxyCfgs, visitorCfgs) is called, releasing visitor ports
// and preventing "bind: address already in use" port collisions.
func TestServiceReconnectClosesOldControlBeforeRun_CANON067(t *testing.T) {
	require := require.New(t)
	initReconnectProxyFactory()

	svr := newReloadTestService(t, nil)

	// Configure visitor and hook proxy on service BEFORE initial login
	bindPort := getFreeTCPPort(t)
	visitorCfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "reconnect-visitor",
			Type:       "stcp",
			BindAddr:   "127.0.0.1",
			ServerName: "reconnect-server",
			SecretKey:  "secret",
			BindPort:   bindPort,
		},
	}
	handoffProxy := &reconnectHandoffProxyConfig{
		TCPProxyConfig: &v1.TCPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{
				Name: "reconnect-handoff-proxy",
				Type: "tcp",
			},
		},
	}
	svr.visitorCfgs = []v1.VisitorConfigurer{visitorCfg}
	svr.proxyCfgs = []v1.ProxyConfigurer{handoffProxy}

	// First login to establish initial control with actively listening visitor port
	currentHandoffCallback.Store(nil)
	svr.loopLoginUntilSuccess(time.Second, true)
	firstCtl := svr.ctl
	require.NotNil(firstCtl)

	// Verify that firstCtl is actively listening on bindPort
	conn1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort), time.Second)
	require.NoError(err, "first control must actively listen on bindPort before reconnect")
	_ = conn1.Close()

	// Setup handover hook to assert that firstCtl is ALREADY closed when second control starts running
	firstCtlClosedBeforeNewRun := atomic.Bool{}
	cb := func() {
		select {
		case <-firstCtl.Done():
			firstCtlClosedBeforeNewRun.Store(true)
		default:
			firstCtlClosedBeforeNewRun.Store(false)
		}
	}
	currentHandoffCallback.Store(&cb)

	// Run second login (reconnect)
	svr.loopLoginUntilSuccess(time.Second, true)
	secondCtl := svr.ctl
	require.NotNil(secondCtl)
	require.NotSame(firstCtl, secondCtl)

	// Verify that old.Close() was executed BEFORE secondCtl.Run() started
	require.True(firstCtlClosedBeforeNewRun.Load(), "first control must be closed before second control starts running")

	// Verify that secondCtl successfully bound the same bindPort without address collision
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort), time.Second)
	require.NoError(err, "second control must successfully bind and listen on the same bindPort without 'address already in use'")
	_ = conn2.Close()

	// Verify first control is closed and done
	select {
	case <-firstCtl.Done():
	default:
		t.Fatal("first control was not done after handoff")
	}
}
