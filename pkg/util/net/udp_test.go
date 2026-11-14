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

package net

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fatedier/golib/pool"
	"github.com/stretchr/testify/require"
)

func TestFakeUDPConnPutPacketAndCloseRace(t *testing.T) {
	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}

	for range 50 {
		fc := NewFakeUDPConn(nil, laddr, raddr)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				buf := pool.GetBuf(16)
				fc.putPacket(buf)
			})
		}
		wg.Go(func() {
			_ = fc.Close()
		})
		wg.Wait()
	}
}

func TestUDPListenerAndFakeUDPConnLifecycle(t *testing.T) {
	ln, err := ListenUDP("127.0.0.1", 0)
	require.NoError(t, err)
	defer ln.Close()

	listenUDPAddr, ok := ln.Addr().(*net.UDPAddr)
	require.True(t, ok)
	require.NotZero(t, listenUDPAddr.Port)

	client1, err := net.DialUDP("udp", nil, listenUDPAddr)
	require.NoError(t, err)
	defer client1.Close()

	// Send two packets from client1; only one FakeUDPConn should be accepted,
	// and both packets should be readable in order on that connection.
	_, err = client1.Write([]byte("pkt-1"))
	require.NoError(t, err)
	_, err = client1.Write([]byte("pkt-2"))
	require.NoError(t, err)

	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	fc, ok := serverConn.(*FakeUDPConn)
	require.True(t, ok)
	require.True(t, fc.IsAccepted())
	require.False(t, fc.IsClosed())
	require.Equal(t, ln.Addr(), fc.LocalAddr())
	require.Equal(t, client1.LocalAddr().String(), fc.RemoteAddr().String())
	require.NoError(t, fc.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, fc.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, fc.SetWriteDeadline(time.Now().Add(time.Second)))

	buf := make([]byte, 32)
	n, err := serverConn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pkt-1", string(buf[:n]))

	n, err = serverConn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pkt-2", string(buf[:n]))

	// Reply via FakeUDPConn.Write back to client1.
	n, err = serverConn.Write([]byte("reply-from-conn"))
	require.NoError(t, err)
	require.Equal(t, len("reply-from-conn"), n)

	require.NoError(t, client1.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, err = client1.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "reply-from-conn", string(buf[:n]))

	// Reply via UDPListener.WriteMsg directly to client1.
	client1Addr, err := net.ResolveUDPAddr("udp", client1.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, ln.WriteMsg([]byte("reply-from-listener"), client1Addr))

	n, err = client1.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "reply-from-listener", string(buf[:n]))

	// Closing FakeUDPConn removes it from active flows; subsequent Read returns EOF
	// and Write returns an error.
	require.NoError(t, serverConn.Close())
	require.True(t, fc.IsClosed())
	_, err = serverConn.Read(buf)
	require.ErrorIs(t, err, io.EOF)
	_, err = serverConn.Write([]byte("after-close"))
	require.Error(t, err)

	// Sending a new packet from client1 after its FakeUDPConn closed creates a new FakeUDPConn.
	_, err = client1.Write([]byte("pkt-after-reopen"))
	require.NoError(t, err)

	serverConn2, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn2.Close()
	n, err = serverConn2.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pkt-after-reopen", string(buf[:n]))

	// Closing the UDPListener is idempotent, unblocks Accept, and rejects WriteMsg.
	require.NoError(t, ln.Close())
	require.NoError(t, ln.Close())
	_, err = ln.Accept()
	require.Error(t, err)
	require.Error(t, ln.WriteMsg([]byte("closed"), client1Addr))
}
