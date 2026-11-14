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

package virtual

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func TestVirtualClientAndPipeConnector(t *testing.T) {
	common := &v1.ClientCommonConfig{}
	vc, err := NewClient(ClientOptions{
		Common: common,
		Spec:   &msg.ClientSpec{Type: "test", AlwaysAuthPass: true},
	})
	require.NoError(t, err)
	require.NotNil(t, vc.PeerListener())
	require.NotNil(t, vc.Service())

	vc.UpdateProxyConfigurer([]v1.ProxyConfigurer{
		&v1.TCPProxyConfig{
			ProxyBaseConfig: v1.ProxyBaseConfig{
				Name: "p1",
				Type: "tcp",
				ProxyBackend: v1.ProxyBackend{
					LocalPort: 8080,
				},
			},
		},
	})
	vc.Close()

	// Test pipeConnector Open, Connect, and Close directly
	ln := netpkg.NewInternalListener()
	pc := &pipeConnector{peerListener: ln}
	require.NoError(t, pc.Open())

	c2, err := pc.Connect()
	require.NoError(t, err)
	c1, err := ln.Accept()
	require.NoError(t, err)
	_ = c1.Close()
	_ = c2.Close()

	require.NoError(t, pc.Close())
	_, err = pc.Connect()
	require.Error(t, err)
}
