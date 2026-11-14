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

package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/group"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/visitor"
)

func TestWorkConnStartWritesStartWorkConn(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))
	clientMsgConn := msg.NewConn(client, msg.NewV2ReadWriter(client))
	workConn := NewWorkConn(serverMsgConn)

	in := &msg.StartWorkConn{ProxyName: "tcp", SrcAddr: "127.0.0.1", SrcPort: 1234}
	type startResult struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan startResult, 1)
	go func() {
		conn, err := workConn.Start(in)
		resultCh <- startResult{conn: conn, err: err}
	}()

	out, err := clientMsgConn.ReadMsg()
	require.NoError(t, err)
	require.Equal(t, in, out)

	result := <-resultCh
	require.NoError(t, result.err)
	// The started stream wraps the same underlying connection so that the
	// owning control keeps observing the stream's lifetime.
	stream, ok := result.conn.(*workConnStream)
	require.True(t, ok)
	require.Same(t, serverMsgConn, stream.Conn)
}

// Closing the started stream must close the owning work connection and run
// its close callback exactly once, so that the control can stop tracking it.
func TestWorkConnStartStreamCloseClosesOwnerAndFiresCallback(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))
	clientMsgConn := msg.NewConn(client, msg.NewV2ReadWriter(client))
	workConn := NewWorkConn(serverMsgConn)

	var callbacks int
	var callbackMu sync.Mutex
	workConn.SetCloseCallback(func() {
		callbackMu.Lock()
		callbacks++
		callbackMu.Unlock()
	})

	// Drain the start message so that the write inside Start can complete.
	go func() {
		_, _ = clientMsgConn.ReadMsg()
	}()

	conn, err := workConn.Start(&msg.StartWorkConn{ProxyName: "tcp"})
	require.NoError(t, err)

	require.NoError(t, conn.Close())
	callbackMu.Lock()
	require.Equal(t, 1, callbacks)
	callbackMu.Unlock()

	// The underlying connection is closed, so the stream is no longer usable.
	_, err = conn.Read(make([]byte, 1))
	require.Error(t, err)

	// Repeated closes keep the callback count at one.
	require.NoError(t, conn.Close())
	callbackMu.Lock()
	require.Equal(t, 1, callbacks)
	callbackMu.Unlock()
}

// Interrupt must close the connection even when the transport close handshake
// would otherwise block.
func TestWorkConnInterruptClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))
	workConn := NewWorkConn(serverMsgConn)

	closed := make(chan struct{})
	workConn.SetCloseCallback(func() { close(closed) })

	require.NoError(t, workConn.Interrupt())

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("interrupt did not close the work connection")
	}
}

func TestGetWorkConnFromPoolStartWorkConnUnchangedForUDPWireV2(t *testing.T) {
	startMsg := getStartWorkConnFromPool(t, &v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "udp", Type: string(v1.ProxyTypeUDP)},
	}, wire.ProtocolV2)

	require.Equal(t, msg.StartWorkConn{ProxyName: "udp"}, startMsg)
}

func TestGetWorkConnFromPoolLeavesRawTCPPayloadUnframed(t *testing.T) {
	startMsg := getStartWorkConnFromPool(t, &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "tcp", Type: string(v1.ProxyTypeTCP)},
	}, wire.ProtocolV2)

	require.Equal(t, msg.StartWorkConn{ProxyName: "tcp"}, startMsg)
}

func getStartWorkConnFromPool(t *testing.T, cfg v1.ProxyConfigurer, wireProtocol string) msg.StartWorkConn {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))
	clientMsgConn := msg.NewConn(client, msg.NewV2ReadWriter(client))
	pxy := &BaseProxy{
		name:         cfg.GetBaseConfig().Name,
		configurer:   cfg,
		poolCount:    0,
		ctx:          context.Background(),
		wireProtocol: wireProtocol,
		getWorkConnFn: func() (*WorkConn, error) {
			return NewWorkConn(serverMsgConn), nil
		},
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := pxy.GetWorkConnFromPool(nil, nil)
		if conn != nil {
			conn.Close()
		}
		errCh <- err
	}()

	var startMsg msg.StartWorkConn
	require.NoError(t, clientMsgConn.ReadMsgInto(&startMsg))
	require.NoError(t, <-errCh)
	return startMsg
}

func TestManagerAddExistGetAndDel(t *testing.T) {
	require := require.New(t)
	pm := NewManager()

	bw, err := types.NewBandwidthQuantity("1MB")
	require.NoError(err)

	cfg := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "p1",
			Type: string(v1.ProxyTypeTCP),
			Transport: v1.ProxyTransport{
				BandwidthLimit:     bw,
				BandwidthLimitMode: types.BandwidthLimitModeServer,
			},
		},
	}
	rc := &controller.ResourceController{}
	userInfo := plugin.UserInfo{User: "alice"}
	loginMsg := &msg.Login{User: "alice"}

	pxy, err := NewProxy(context.Background(), &Options{
		UserInfo:           userInfo,
		LoginMsg:           loginMsg,
		PoolCount:          1,
		ResourceController: rc,
		Configurer:         cfg,
		ServerCfg:          &v1.ServerConfig{SubDomainHost: "frps.com"},
	})
	require.NoError(err)
	require.Equal("p1", pxy.GetName())
	require.Equal(1, pxy.GetUsedPortsNum())
	require.Same(rc, pxy.GetResourceController())
	require.Equal(userInfo, pxy.GetUserInfo())
	require.Same(loginMsg, pxy.GetLoginMsg())
	require.NotNil(pxy.GetLimiter())
	require.Same(cfg, pxy.GetConfigurer())
	require.NotNil(pxy.Context())

	require.False(pm.Exist("p1"))
	require.NoError(pm.Add("p1", pxy))
	require.True(pm.Exist("p1"))

	// Duplicate Add must error
	require.ErrorContains(pm.Add("p1", pxy), "already in use")

	got, ok := pm.GetByName("p1")
	require.True(ok)
	require.Same(pxy, got)

	pm.Del("p1")
	require.False(pm.Exist("p1"))
	_, ok = pm.GetByName("p1")
	require.False(ok)
}

func TestAllProxyTypesRunAndClose(t *testing.T) {
	require := require.New(t)

	tcpPM := ports.NewManager("tcp", "127.0.0.1", []types.PortsRange{{Start: 42000, End: 42100}})
	defer tcpPM.Close()
	udpPM := ports.NewManager("udp", "127.0.0.1", []types.PortsRange{{Start: 42101, End: 42200}})
	defer udpPM.Close()

	routers := vhost.NewRouters()
	rp := vhost.NewHTTPReverseProxy(vhost.HTTPReverseProxyOptions{}, routers)

	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer httpsLn.Close()
	httpsMuxer, err := vhost.NewHTTPSMuxer(httpsLn, time.Second)
	require.NoError(err)

	muxLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer muxLn.Close()
	httpConnectMuxer, err := tcpmux.NewHTTPConnectTCPMuxer(muxLn, false, time.Second)
	require.NoError(err)

	nhc, err := nathole.NewController(time.Minute)
	require.NoError(err)

	rc := &controller.ResourceController{
		VisitorManager:         visitor.NewManager(),
		TCPPortManager:         tcpPM,
		UDPPortManager:         udpPM,
		TCPGroupCtl:            group.NewTCPGroupCtl(tcpPM),
		HTTPGroupCtl:           group.NewHTTPGroupController(routers),
		HTTPSGroupCtl:          group.NewHTTPSGroupController(httpsMuxer),
		TCPMuxGroupCtl:         group.NewTCPMuxGroupCtl(httpConnectMuxer),
		HTTPReverseProxy:       rp,
		VhostHTTPSMuxer:        httpsMuxer,
		TCPMuxHTTPConnectMuxer: httpConnectMuxer,
		NatHoleController:      nhc,
		PluginManager:          plugin.NewManager(),
	}

	serverCfg := &v1.ServerConfig{
		ProxyBindAddr:         "127.0.0.1",
		SubDomainHost:         "example.com",
		VhostHTTPPort:         8080,
		VhostHTTPSPort:        8443,
		TCPMuxHTTPConnectPort: 8888,
	}

	newOpts := func(cfg v1.ProxyConfigurer) *Options {
		return &Options{
			UserInfo:           plugin.UserInfo{User: "u1"},
			LoginMsg:           &msg.Login{User: "u1"},
			PoolCount:          1,
			ResourceController: rc,
			Configurer:         cfg,
			ServerCfg:          serverCfg,
			EncryptionKey:      []byte("secret-key"),
			WireProtocol:       wire.ProtocolV2,
			GetWorkConnFn: func() (*WorkConn, error) {
				c1, c2 := net.Pipe()
				go func() {
					clientMsg := msg.NewConn(c1, msg.NewV2ReadWriter(c1))
					var start msg.StartWorkConn
					_ = clientMsg.ReadMsgInto(&start)
					_ = c1.Close()
				}()
				return NewWorkConn(msg.NewConn(c2, msg.NewV2ReadWriter(c2))), nil
			},
		}
	}

	// 1. Standalone TCPProxy & Grouped TCPProxy
	tcpPxy, err := NewProxy(context.Background(), newOpts(&v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "tcp-1", Type: "tcp"},
	}))
	require.NoError(err)
	addr, err := tcpPxy.Run()
	require.NoError(err)
	require.NotEmpty(addr)
	tcpPxy.Close()

	tcpGrpPxy, err := NewProxy(context.Background(), newOpts(&v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name:         "tcp-grp-1",
			Type:         "tcp",
			LoadBalancer: v1.LoadBalancerConfig{Group: "g1", GroupKey: "k1"},
		},
	}))
	require.NoError(err)
	addr, err = tcpGrpPxy.Run()
	require.NoError(err)
	require.NotEmpty(addr)
	tcpGrpPxy.Close()

	// 2. HTTPProxy (standalone, grouped, and GetRealConn)
	httpPxy, err := NewProxy(context.Background(), newOpts(&v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name:      "http-1",
			Type:      "http",
			Transport: v1.ProxyTransport{UseEncryption: true, UseCompression: true},
		},
		DomainConfig: v1.DomainConfig{CustomDomains: []string{"a.example.com"}, SubDomain: "sub"},
	}))
	require.NoError(err)
	addr, err = httpPxy.Run()
	require.NoError(err)
	require.Contains(addr, "a.example.com:8080")
	require.Contains(addr, "sub.example.com:8080")

	realConn, err := httpPxy.(*HTTPProxy).GetRealConn("127.0.0.1:54321")
	require.NoError(err)
	_ = realConn.Close()
	httpPxy.Close()

	// 3. HTTPSProxy (standalone and grouped)
	httpsPxy, err := NewProxy(context.Background(), newOpts(&v1.HTTPSProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name:         "https-1",
			Type:         "https",
			LoadBalancer: v1.LoadBalancerConfig{Group: "hg1", GroupKey: "hk1"},
		},
		DomainConfig: v1.DomainConfig{CustomDomains: []string{"sec.example.com"}},
	}))
	require.NoError(err)
	addr, err = httpsPxy.Run()
	require.NoError(err)
	require.Contains(addr, "sec.example.com:8443")
	httpsPxy.Close()

	// 4. TCPMuxProxy (httpconnect & invalid multiplexer)
	muxPxy, err := NewProxy(context.Background(), newOpts(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "mux-1", Type: "tcpmux"},
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"mux.example.com"}},
		Multiplexer:     string(v1.TCPMultiplexerHTTPConnect),
	}))
	require.NoError(err)
	addr, err = muxPxy.Run()
	require.NoError(err)
	require.Contains(addr, "mux.example.com:8888")
	muxPxy.Close()

	badMuxPxy, err := NewProxy(context.Background(), newOpts(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "mux-bad", Type: "tcpmux"},
		Multiplexer:     "invalid",
	}))
	require.NoError(err)
	_, err = badMuxPxy.Run()
	require.ErrorContains(err, "unknown multiplexer")

	// 5. STCPProxy & SUDPProxy
	stcpPxy, err := NewProxy(context.Background(), newOpts(&v1.STCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "stcp-1", Type: "stcp"},
		Secretkey:       "sk",
	}))
	require.NoError(err)
	_, err = stcpPxy.Run()
	require.NoError(err)
	stcpPxy.Close()

	sudpPxy, err := NewProxy(context.Background(), newOpts(&v1.SUDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "sudp-1", Type: "sudp"},
		Secretkey:       "sk",
	}))
	require.NoError(err)
	_, err = sudpPxy.Run()
	require.NoError(err)
	sudpPxy.Close()

	// 6. XTCPProxy
	xtcpPxy, err := NewProxy(context.Background(), newOpts(&v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "xtcp-1", Type: "xtcp"},
		Secretkey:       "sk",
	}))
	require.NoError(err)
	_, err = xtcpPxy.Run()
	require.NoError(err)
	xtcpPxy.Close()
}

func TestSUDPMixedPacketEncodingAndBridge(t *testing.T) {
	require := require.New(t)

	// Codec normalization validation
	_, err := normalizeUDPPacketCodec(wire.ProtocolV1, wire.UDPPacketCodecBinary)
	require.ErrorContains(err, "requires wire protocol v2")
	_, err = normalizeUDPPacketCodec(wire.ProtocolV2, "unknown-codec")
	require.ErrorContains(err, "unsupported UDP packet codec")
	_, err = normalizeUDPPacketCodec("v99", "")
	require.ErrorContains(err, "unsupported wire protocol")

	mixed, err := isMixedSUDPPacketEncoding(wire.ProtocolV1, "", wire.ProtocolV2, wire.UDPPacketCodecBinary)
	require.NoError(err)
	require.True(mixed)

	mixed, err = isMixedSUDPPacketEncoding(wire.ProtocolV2, wire.UDPPacketCodecBinary, wire.ProtocolV2, wire.UDPPacketCodecBinary)
	require.NoError(err)
	require.False(mixed)

	// Bridge between v1 proxy and v2+binary visitor
	proxyClient, proxyServer := net.Pipe()
	visitorClient, visitorServer := net.Pipe()
	defer proxyClient.Close()
	defer proxyServer.Close()
	defer visitorClient.Close()
	defer visitorServer.Close()

	proxyRW, err := msg.NewUDPPacketReadWriter(proxyClient, wire.ProtocolV1, "")
	require.NoError(err)
	visitorRW, err := msg.NewUDPPacketReadWriter(visitorClient, wire.ProtocolV2, wire.UDPPacketCodecBinary)
	require.NoError(err)

	done := make(chan struct{})
	var inCount, outCount int64
	var bridgeErrs []error
	go func() {
		inCount, outCount, bridgeErrs = joinSUDPMessageBridge(
			proxyServer,
			visitorServer,
			wire.ProtocolV1,
			"",
			wire.ProtocolV2,
			wire.UDPPacketCodecBinary,
			nil,
		)
		close(done)
	}()

	remoteUDP := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}

	// Visitor sends Ping (dropped to proxy) + UDPPacket (forwarded to proxy)
	go func() {
		_ = visitorRW.WriteMsg(&msg.Ping{})
		_ = visitorRW.WriteMsg(&msg.UDPPacket{
			Content:    []byte("hello-from-visitor"),
			RemoteAddr: remoteUDP,
		})
	}()

	gotAtProxy, err := proxyRW.ReadMsg()
	require.NoError(err)
	require.Equal([]byte("hello-from-visitor"), gotAtProxy.(*msg.UDPPacket).Content)

	// Proxy sends Ping (forwarded to visitor) + UDPPacket (forwarded to visitor)
	go func() {
		_ = proxyRW.WriteMsg(&msg.Ping{})
		_ = proxyRW.WriteMsg(&msg.UDPPacket{
			Content:    []byte("reply-from-proxy"),
			RemoteAddr: remoteUDP,
		})
	}()

	gotPingAtVisitor, err := visitorRW.ReadMsg()
	require.NoError(err)
	require.IsType(&msg.Ping{}, gotPingAtVisitor)

	gotPktAtVisitor, err := visitorRW.ReadMsg()
	require.NoError(err)
	require.Equal([]byte("reply-from-proxy"), gotPktAtVisitor.(*msg.UDPPacket).Content)

	_ = proxyClient.Close()
	_ = visitorClient.Close()
	<-done
	require.Empty(bridgeErrs)
	require.Equal(int64(len("hello-from-visitor")), inCount)
	require.Equal(int64(len("reply-from-proxy")), outCount)
}
