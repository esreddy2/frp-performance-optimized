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

//go:build !frps

package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/client/event"
	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/xlog"
)

func TestHandleTCPWorkConnectionRejectsInvalidAddress(t *testing.T) {
	workConn, peerConn := net.Pipe()
	defer peerConn.Close()

	pxy := &BaseProxy{
		baseCfg: &v1.ProxyBaseConfig{},
		xl:      xlog.New(),
	}
	pxy.HandleTCPWorkConnection(workConn, &msg.StartWorkConn{
		SrcAddr: "[",
		SrcPort: 1,
	}, nil)

	buffer := make([]byte, 1)
	_, err := peerConn.Read(buffer)
	require.ErrorIs(t, err, io.EOF)
}

func TestHandleTCPWorkConnectionTProxyRejectsNilSrcAddr(t *testing.T) {
	workConn, peerConn := net.Pipe()
	defer peerConn.Close()

	// Start a local listener that must NOT be dialed when SrcAddr is empty under tproxy.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	pxy := &BaseProxy{
		baseCfg: &v1.ProxyBaseConfig{
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   addr.IP.String(),
				LocalPort: addr.Port,
			},
			Transport: v1.ProxyTransport{
				ProxyProtocol: "tproxy",
			},
		},
		xl: xlog.New(),
	}
	pxy.HandleTCPWorkConnection(workConn, &msg.StartWorkConn{}, nil)

	buffer := make([]byte, 1)
	_, readErr := peerConn.Read(buffer)
	require.ErrorIs(t, readErr, io.EOF)
	select {
	case <-accepted:
		t.Fatal("tproxy must not dial local service when SrcAddr is empty")
	default:
	}
}

func TestHandleTCPWorkConnectionPartialSrcAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	received := make(chan string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	workConn, peerConn := net.Pipe()
	defer peerConn.Close()

	addr := ln.Addr().(*net.TCPAddr)
	pxy := &BaseProxy{
		baseCfg: &v1.ProxyBaseConfig{
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   addr.IP.String(),
				LocalPort: addr.Port,
			},
			Transport: v1.ProxyTransport{
				ProxyProtocol: "v1",
			},
		},
		xl: xlog.New(),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		pxy.HandleTCPWorkConnection(workConn, &msg.StartWorkConn{
			SrcAddr: "203.0.113.10",
			SrcPort: 0,
			DstAddr: "127.0.0.1",
			DstPort: 8080,
		}, nil)
	}()

	headerLine := <-received
	require.Contains(t, headerLine, "PROXY TCP4 203.0.113.10 127.0.0.1 0 8080")
	_ = peerConn.Close()
	<-done
}

type fakeMsgTransporter struct {
	transport.MessageTransporter
	mu   sync.Mutex
	sent []msg.Message
}

func (f *fakeMsgTransporter) Send(m msg.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func TestBaseProxyPluginAndEncryptedCompressedWorkConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, readErr := conn.Read(buf)
		if readErr == nil {
			_, _ = conn.Write([]byte("echo:" + string(buf[:n])))
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	bw, err := types.NewBandwidthQuantity("1MB")
	require.NoError(t, err)

	tcpCfg := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "enc-comp-tcp",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   addr.IP.String(),
				LocalPort: addr.Port,
			},
			Transport: v1.ProxyTransport{
				UseEncryption:      true,
				UseCompression:     true,
				BandwidthLimit:     bw,
				BandwidthLimitMode: types.BandwidthLimitModeClient,
			},
		},
	}

	clientCfg := &v1.ClientCommonConfig{}
	require.NoError(t, clientCfg.Complete())
	encKey := []byte("0123456789abcdef")

	pxy := NewProxy(context.Background(), tcpCfg, clientCfg, encKey, &fakeMsgTransporter{}, nil, "", nil)
	require.NotNil(t, pxy)
	genPxy, ok := pxy.(*GeneralTCPProxy)
	require.True(t, ok)
	require.Equal(t, "enc-comp-tcp", genPxy.GetName())
	require.NoError(t, pxy.Run())

	// Callback returning false intercepts InWorkConn before HandleTCPWorkConnection
	intercepted := false
	pxy.SetInWorkConnCallback(func(_ *v1.ProxyBaseConfig, c net.Conn, _ *msg.StartWorkConn) bool {
		intercepted = true
		_ = c.Close()
		return false
	})
	c1, c2 := net.Pipe()
	pxy.InWorkConn(c1, &msg.StartWorkConn{})
	require.True(t, intercepted)
	_ = c2.Close()

	// Callback returning true continues to HandleTCPWorkConnection with encryption + compression + rate limiter
	pxy.SetInWorkConnCallback(func(_ *v1.ProxyBaseConfig, _ net.Conn, _ *msg.StartWorkConn) bool {
		return true
	})

	workConn, serverSide := net.Pipe()
	defer serverSide.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pxy.InWorkConn(workConn, &msg.StartWorkConn{})
	}()

	remoteRWC, recycle, err := genPxy.wrapWorkConn(serverSide, encKey)
	require.NoError(t, err)
	if recycle != nil {
		defer recycle()
	}

	_, err = remoteRWC.Write([]byte("hello"))
	require.NoError(t, err)
	reply := make([]byte, 64)
	n, err := remoteRWC.Read(reply)
	require.NoError(t, err)
	require.Equal(t, "echo:hello", string(reply[:n]))
	_ = remoteRWC.Close()
	_ = serverSide.Close()
	<-done
	pxy.Close()

	// Also verify BaseProxy with a static_file plugin
	pluginCfg := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "plugin-tcp",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				Plugin: v1.TypedClientPluginOptions{
					Type: v1.PluginStaticFile,
					ClientPluginOptions: &v1.StaticFilePluginOptions{
						LocalPath: t.TempDir(),
					},
				},
			},
		},
	}
	pluginPxy := NewProxy(context.Background(), pluginCfg, clientCfg, nil, &fakeMsgTransporter{}, nil, "", nil)
	require.NoError(t, pluginPxy.Run())
	pluginPxy.Close()
}

func TestProxyManagerLifecycleAndEvents(t *testing.T) {
	transporter := &fakeMsgTransporter{}
	clientCfg := &v1.ClientCommonConfig{User: "alice"}
	require.NoError(t, clientCfg.Complete())

	pm := NewManager(context.Background(), clientCfg, []byte("secret"), transporter, nil, "", nil)
	pm.SetInWorkConnCallback(func(_ *v1.ProxyBaseConfig, c net.Conn, _ *msg.StartWorkConn) bool {
		_ = c.Close()
		return false
	})

	// HandleEvent dispatches StartProxyPayload, CloseProxyPayload, and rejects unknown payload
	require.NoError(t, pm.HandleEvent(&event.StartProxyPayload{NewProxyMsg: &msg.NewProxy{ProxyName: "p1"}}))
	require.NoError(t, pm.HandleEvent(&event.CloseProxyPayload{CloseProxyMsg: &msg.CloseProxy{ProxyName: "p1"}}))
	require.ErrorIs(t, pm.HandleEvent("invalid"), event.ErrPayloadType)
	require.Len(t, transporter.sent, 2)

	// StartProxy on non-existent proxy returns error
	require.ErrorContains(t, pm.StartProxy("missing", "", ""), "not found")

	p1 := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "p1",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   "127.0.0.1",
				LocalPort: 8080,
			},
		},
	}
	pm.UpdateAll([]v1.ProxyConfigurer{p1})
	require.Len(t, pm.GetAllProxyStatus(), 1)
	st, ok := pm.GetProxyStatus("p1")
	require.True(t, ok)
	require.Equal(t, "p1", st.Name)
	_, ok = pm.GetProxyStatus("unknown")
	require.False(t, ok)

	// Wait for checkWorker to transition p1 to ProxyPhaseWaitStart, then StartProxy
	require.Eventually(t, func() bool {
		s, ok := pm.GetProxyStatus("p1")
		return ok && s.Phase == ProxyPhaseWaitStart
	}, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, pm.StartProxy("p1", ":6000", ""))
	st, ok = pm.GetProxyStatus("p1")
	require.True(t, ok)
	require.Equal(t, ProxyPhaseRunning, st.Phase)
	require.Equal(t, ":6000", st.RemoteAddr)

	// HandleWorkConn for known and unknown proxy
	c1, c2 := net.Pipe()
	pm.HandleWorkConn("p1", c1, &msg.StartWorkConn{})
	_ = c2.Close()

	u1, u2 := net.Pipe()
	pm.HandleWorkConn("unknown", u1, &msg.StartWorkConn{})
	_, err := u2.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	_ = u2.Close()

	// UpdateAll with modified config replaces p1, then empty slice removes it
	p1Updated := p1.Clone()
	p1Updated.GetBaseConfig().LocalPort = 8081
	pm.UpdateAll([]v1.ProxyConfigurer{p1Updated})
	pm.UpdateAll(nil)
	require.Empty(t, pm.GetAllProxyStatus())

	pm.Close()
}
