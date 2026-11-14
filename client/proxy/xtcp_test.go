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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/util/xlog"
)

func TestReadNatHoleSidUsesSelectedWireProtocol(t *testing.T) {
	for _, tc := range []struct {
		name         string
		wireProtocol string
	}{
		{name: "v2", wireProtocol: wire.ProtocolV2},
		{name: "v1", wireProtocol: wire.ProtocolV1},
		{name: "default", wireProtocol: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			setPipeDeadline(t, client, server)

			errCh := make(chan error, 1)
			go func() {
				writerRW, err := msg.NewReadWriter(server, tc.wireProtocol)
				if err != nil {
					errCh <- err
					return
				}
				writer := msg.NewConn(server, writerRW)
				errCh <- writer.WriteMsg(&msg.NatHoleSid{Sid: "sid"})
			}()

			out, err := readNatHoleSid(client, tc.wireProtocol)
			require.NoError(t, err)
			require.Equal(t, "sid", out.Sid)
			require.NoError(t, <-errCh)
		})
	}
}

func setPipeDeadline(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for _, conn := range conns {
		require.NoError(t, conn.SetDeadline(deadline))
	}
}

func TestXTCPProxyConstructorAndInWorkConnError(t *testing.T) {
	base := &BaseProxy{
		baseCfg: &v1.ProxyBaseConfig{Name: "xtcp-test"},
		clientCfg: &v1.ClientCommonConfig{
			Transport: v1.ClientTransportConfig{WireProtocol: wire.ProtocolV1},
		},
		xl:  xlog.New(),
		ctx: context.Background(),
	}

	require.Nil(t, NewXTCPProxy(base, &v1.TCPProxyConfig{}))

	xtcpCfg := &v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "xtcp-test", Type: "xtcp"},
	}
	pxy := NewXTCPProxy(base, xtcpCfg)
	require.NotNil(t, pxy)

	// InWorkConn when peer closes immediately returns cleanly after readNatHoleSid error
	c1, c2 := net.Pipe()
	_ = c2.Close()
	pxy.InWorkConn(c1, &msg.StartWorkConn{})
}
