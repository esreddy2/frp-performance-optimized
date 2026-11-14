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

package vnet

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// TestVNetBCP38IngressFilterAndAntiHijack verifies CANON-046:
// 1. Ingress filtering drops unspecified, multicast, loopback, broadcast, and gateway spoofed IPs.
// 2. Anti-hijack prevents a connection from stealing an IP registered by another connection.
func TestVNetBCP38IngressFilterAndAntiHijack(t *testing.T) {
	require := require.New(t)
	ctrl := NewController(v1.VirtualNetConfig{Address: "100.86.0.1/24"})

	conn1, peer1 := net.Pipe()
	t.Cleanup(func() {
		_ = conn1.Close()
		_ = peer1.Close()
	})
	conn2, peer2 := net.Pipe()
	t.Cleanup(func() {
		_ = conn2.Close()
		_ = peer2.Close()
	})

	// 1. Ingress filtering of invalid/spoofed source IPs
	require.False(ctrl.validateAndRegisterSrcIP(nil, conn1))
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("0.0.0.0"), conn1))
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("::"), conn1))
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("224.0.0.1"), conn1))  // multicast
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("ff02::1"), conn1))    // IPv6 multicast
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("127.0.0.1"), conn1))  // loopback
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("::1"), conn1))        // IPv6 loopback
	require.False(ctrl.validateAndRegisterSrcIP(net.IPv4bcast, conn1))             // 255.255.255.255
	require.False(ctrl.validateAndRegisterSrcIP(net.ParseIP("100.86.0.1"), conn1)) // local gateway spoofing

	// 2. Valid source IP registration for conn1
	validIP1 := net.ParseIP("172.16.10.5")
	require.True(ctrl.validateAndRegisterSrcIP(validIP1, conn1))

	// Re-registering by same connection succeeds (fast path)
	require.True(ctrl.validateAndRegisterSrcIP(validIP1, conn1))

	// 3. Hijack attempt by conn2 MUST be rejected
	require.False(ctrl.validateAndRegisterSrcIP(validIP1, conn2))

	// Verify route still points to conn1
	routedConn, err := ctrl.serverRouter.findConnBySrc(validIP1)
	require.NoError(err)
	require.Same(conn1, routedConn)

	// 4. When conn1 releases/cleans up, conn2 is allowed to register
	ctrl.serverRouter.cleanupConnIPs(conn1)
	require.True(ctrl.validateAndRegisterSrcIP(validIP1, conn2))

	routedConn, err = ctrl.serverRouter.findConnBySrc(validIP1)
	require.NoError(err)
	require.Same(conn2, routedConn)
}

// TestVNetTTLExpirationAndHopLimit verifies CANON-059:
// Decrements TTL/HopLimit, dropping packets with TTL/HopLimit <= 1 to break loops.
func TestVNetTTLExpirationAndHopLimit(t *testing.T) {
	require := require.New(t)
	ctrl := NewController(v1.VirtualNetConfig{Address: "10.0.0.1/24"})

	targetConn, targetPeer := net.Pipe()
	t.Cleanup(func() {
		_ = targetConn.Close()
		_ = targetPeer.Close()
	})
	ctrl.serverRouter.registerSrcIP(net.ParseIP("10.0.0.2"), targetConn)

	// Case 1: IPv4 packet with TTL = 1 -> Dropped (never sent to targetConn)
	pktTTL1 := buildIPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), []byte("drop-me"))
	pktTTL1[8] = 1 // TTL = 1
	ctrl.handlePacket(pktTTL1)

	// Channel read should not receive any packet (use non-blocking check)
	readCh := make(chan []byte, 1)
	go func() {
		data, _ := ReadMessage(targetPeer)
		readCh <- data
	}()
	select {
	case <-readCh:
		t.Fatal("expected packet with TTL=1 to be dropped, but was forwarded")
	case <-time.After(100 * time.Millisecond):
		// Expected: dropped
	}

	// Case 2: IPv4 packet with TTL = 64 -> Forwarded with TTL = 63
	pktTTL64 := buildIPv4Packet(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), []byte("forward-me"))
	pktTTL64[8] = 64
	ctrl.handlePacket(pktTTL64)

	select {
	case got := <-readCh:
		header, err := ipv4.ParseHeader(got)
		require.NoError(err)
		require.Equal(63, header.TTL)
		require.Equal([]byte("forward-me"), got[header.Len:])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded packet with decremented TTL")
	}

	// Case 3: IPv6 packet with HopLimit = 1 -> Dropped
	ctrl.serverRouter.registerSrcIP(net.ParseIP("fd00::2"), targetConn)
	pktHop1 := buildIPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), []byte("drop-v6"))
	pktHop1[7] = 1 // Hop Limit = 1
	ctrl.handlePacket(pktHop1)

	go func() {
		data, _ := ReadMessage(targetPeer)
		readCh <- data
	}()
	select {
	case <-readCh:
		t.Fatal("expected IPv6 packet with HopLimit=1 to be dropped, but was forwarded")
	case <-time.After(100 * time.Millisecond):
		// Expected: dropped
	}

	// Case 4: IPv6 packet with HopLimit = 64 -> Forwarded with HopLimit = 63
	pktHop64 := buildIPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd00::2"), []byte("forward-v6"))
	pktHop64[7] = 64
	ctrl.handlePacket(pktHop64)

	select {
	case got := <-readCh:
		header, err := ipv6.ParseHeader(got)
		require.NoError(err)
		require.Equal(63, header.HopLimit)
		require.Equal([]byte("forward-v6"), got[40:])
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwarded IPv6 packet with decremented HopLimit")
	}
}

// TestVNetTunDeviceWrapperLargePackets verifies CANON-058:
// Packets larger than 1420 bytes are not truncated and satisfy io.Writer contract.
func TestVNetTunDeviceWrapperLargePackets(t *testing.T) {
	require := require.New(t)

	var writtenPayloads [][]byte
	fake := &fakeTunDevice{
		writeFn: func(bufs [][]byte, offset int) (int, error) {
			for _, buf := range bufs {
				packet := make([]byte, len(buf)-offset)
				copy(packet, buf[offset:])
				writtenPayloads = append(writtenPayloads, packet)
			}
			return len(bufs), nil
		},
	}

	wrapper := newTunDeviceWrapper(fake)

	// Write 1500 bytes (standard Ethernet MTU)
	pkt1500 := bytes.Repeat([]byte("A"), 1500)
	n, err := wrapper.Write(pkt1500)
	require.NoError(err)
	require.Equal(1500, n, "Write must return n == len(p) according to io.Writer contract")
	require.Equal(pkt1500, writtenPayloads[0])

	// Write 2048 bytes (jumbo packet)
	pkt2048 := bytes.Repeat([]byte("B"), 2048)
	n, err = wrapper.Write(pkt2048)
	require.NoError(err)
	require.Equal(2048, n)
	require.Equal(pkt2048, writtenPayloads[1])
}

// TestVNetControllerStopLifecycleCleanShutdown verifies CANON-056:
// Controller.Stop closes active conns and cancels read loops.
func TestVNetControllerStopLifecycleCleanShutdown(t *testing.T) {
	require := require.New(t)
	ctrl := NewController(v1.VirtualNetConfig{Address: "100.86.0.1/24"})

	tunConn, tunPeer := net.Pipe()
	t.Cleanup(func() {
		_ = tunConn.Close()
		_ = tunPeer.Close()
	})
	ctrl.tun = tunConn

	clientConn, clientPeer := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = clientPeer.Close()
	})
	ctrl.trackConn(clientConn)

	serverConn, serverPeer := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = serverPeer.Close()
	})
	ctrl.trackConn(serverConn)

	// Stop must close tracked connections and tun
	require.NoError(ctrl.Stop())

	// Read on peer should fail with EOF since conn was closed by Stop()
	buf := make([]byte, 10)
	_, err := clientPeer.Read(buf)
	require.Error(err)

	_, err = serverPeer.Read(buf)
	require.Error(err)
}
