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
	"io"
	"os"
	"testing"
	"time"

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

func TestBufferedPipe(t *testing.T) {
	require := require.New(t)

	c1, c2 := NewBufferedPipe(16)
	defer c1.Close()
	defer c2.Close()

	// 1. Buffered non-blocking writes: can write multiple chunks without blocking
	msg1 := []byte("hello from 1")
	msg2 := []byte("world from 1")
	n, err := c1.Write(msg1)
	require.NoError(err)
	require.Equal(len(msg1), n)

	n, err = c1.Write(msg2)
	require.NoError(err)
	require.Equal(len(msg2), n)

	// Read from c2
	buf := make([]byte, len(msg1)+len(msg2))
	n, err = c2.Read(buf[:len(msg1)])
	require.NoError(err)
	require.Equal(msg1, buf[:n])

	n, err = c2.Read(buf[len(msg1):])
	require.NoError(err)
	require.Equal(msg2, buf[len(msg1):len(msg1)+n])

	// 2. Reverse direction: c2 -> c1
	msg3 := []byte("response from 2")
	n, err = c2.Write(msg3)
	require.NoError(err)
	require.Equal(len(msg3), n)

	buf3 := make([]byte, len(msg3))
	n, err = c1.Read(buf3)
	require.NoError(err)
	require.Equal(msg3, buf3[:n])

	// 3. Addresses and deadlines
	require.Equal("pipe", c1.LocalAddr().Network())
	require.Equal("pipe", c1.RemoteAddr().Network())

	// Read deadline in the past should immediately error
	require.NoError(c2.SetReadDeadline(time.Now().Add(-time.Second)))
	_, err = c2.Read(buf)
	require.ErrorIs(err, os.ErrDeadlineExceeded)

	// Reset read deadline
	require.NoError(c2.SetReadDeadline(time.Time{}))

	// 4. Closing c1 causes EOF on c2 read
	require.NoError(c1.Close())
	_, err = c2.Read(buf)
	require.ErrorIs(err, io.EOF)
}
