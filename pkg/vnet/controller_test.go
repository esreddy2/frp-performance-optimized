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
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func buildIPv4Packet(src, dst net.IP, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = (4 << 4) | 5 // Version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

func buildIPv6Packet(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 40+len(payload))
	pkt[0] = 6 << 4 // Version 6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(payload)))
	pkt[6] = 17 // Next Header: UDP
	pkt[7] = 64 // Hop Limit
	copy(pkt[8:24], src.To16())
	copy(pkt[24:40], dst.To16())
	copy(pkt[40:], payload)
	return pkt
}

// TestClientRouterDeleteRouteRequiresMatchingConnection verifies that a stale
// visitor cannot remove a replacement route registered under the same name.
func TestClientRouterDeleteRouteRequiresMatchingConnection(t *testing.T) {
	require := require.New(t)
	controller := NewController(v1.VirtualNetConfig{})

	_, route, err := net.ParseCIDR("10.1.0.1/32")
	require.NoError(err)

	oldConn, oldPeer := net.Pipe()
	t.Cleanup(func() {
		_ = oldConn.Close()
		_ = oldPeer.Close()
	})
	replacementConn, replacementPeer := net.Pipe()
	t.Cleanup(func() {
		_ = replacementConn.Close()
		_ = replacementPeer.Close()
	})

	controller.clientRouter.addRoute("vnet-visitor", []net.IPNet{*route}, oldConn)
	controller.clientRouter.addRoute("vnet-visitor", []net.IPNet{*route}, replacementConn)

	require.False(controller.UnregisterClientRoute("vnet-visitor", oldConn))
	got, err := controller.clientRouter.findConn(net.ParseIP("10.1.0.1"))
	require.NoError(err)
	require.Same(replacementConn, got)

	// The read loop for an old connection can exit after a replacement route
	// has already been registered. Its deferred cleanup must keep the new owner.
	controller.clientRouter.removeConnRoute(oldConn)
	got, err = controller.clientRouter.findConn(net.ParseIP("10.1.0.1"))
	require.NoError(err)
	require.Same(replacementConn, got)

	require.True(controller.UnregisterClientRoute("vnet-visitor", replacementConn))
	_, err = controller.clientRouter.findConn(net.ParseIP("10.1.0.1"))
	require.Error(err)
}

func TestReadWriteMessage(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello virtual network")
	require.NoError(t, WriteMessage(&buf, payload))

	got, err := ReadMessage(&buf)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	// Empty message error on write
	require.ErrorContains(t, WriteMessage(&buf, nil), "message data length is 0")

	// Oversized message error on write
	oversized := make([]byte, maxMessageSize+1)
	require.ErrorContains(t, WriteMessage(&buf, oversized), "message too large")

	// Zero length on read
	buf.Reset()
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(0)))
	_, err = ReadMessage(&buf)
	require.ErrorContains(t, err, "message length is 0")

	// Oversized length on read
	buf.Reset()
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(maxMessageSize+1)))
	_, err = ReadMessage(&buf)
	require.ErrorContains(t, err, "message too large")

	// Truncated payload on read
	buf.Reset()
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, uint32(10)))
	buf.WriteString("short")
	_, err = ReadMessage(&buf)
	require.ErrorContains(t, err, "read message data error")

	// EOF on reading length
	buf.Reset()
	_, err = ReadMessage(&buf)
	require.ErrorContains(t, err, "read message length error")
}

func TestParseRoutes(t *testing.T) {
	routes, err := ParseRoutes([]string{"10.0.0.0/8", "fd00::/64"})
	require.NoError(t, err)
	require.Len(t, routes, 2)

	_, err = ParseRoutes([]string{"10.0.0.0/8", "invalid-cidr"})
	require.ErrorContains(t, err, "parse route invalid-cidr error")
}

func TestControllerClientAndServerLoopsAndRouting(t *testing.T) {
	controller := NewController(v1.VirtualNetConfig{Address: "100.86.0.1/24"})
	// Stop before tun is initialized is a no-op
	require.NoError(t, controller.Stop())

	tunConn, tunPeer := net.Pipe()
	t.Cleanup(func() {
		_ = tunConn.Close()
		_ = tunPeer.Close()
	})
	controller.tun = tunConn

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- controller.Run()
	}()

	// Register a client route for 10.20.0.0/16
	routes, err := ParseRoutes([]string{"10.20.0.0/16", "fd20::/64"})
	require.NoError(t, err)

	clientConn, clientPeer := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = clientPeer.Close()
	})
	controller.RegisterClientRoute(context.Background(), "client-route", routes, clientConn)

	// 1. Send IPv4 and IPv6 packets from tunPeer -> Controller.Run -> handlePacket -> clientPeer
	v4ToClient := buildIPv4Packet(net.ParseIP("100.86.0.1"), net.ParseIP("10.20.1.2"), []byte("ping-v4"))
	_, err = tunPeer.Write(v4ToClient)
	require.NoError(t, err)
	gotMsg, err := ReadMessage(clientPeer)
	require.NoError(t, err)
	v4Expected := make([]byte, len(v4ToClient))
	copy(v4Expected, v4ToClient)
	v4Expected[8]--
	require.Equal(t, v4Expected, gotMsg)

	v6ToClient := buildIPv6Packet(net.ParseIP("fd00::1"), net.ParseIP("fd20::2"), []byte("ping-v6"))
	_, err = tunPeer.Write(v6ToClient)
	require.NoError(t, err)
	gotMsg, err = ReadMessage(clientPeer)
	require.NoError(t, err)
	v6Expected := make([]byte, len(v6ToClient))
	copy(v6Expected, v6ToClient)
	v6Expected[7]--
	require.Equal(t, v6Expected, gotMsg)

	// Also test handlePacket edge cases directly (empty, unknown version, truncated IPv4/IPv6, unroutable)
	controller.handlePacket(nil)
	controller.handlePacket([]byte{0x10, 0x00}) // IP version 1 (unknown)
	controller.handlePacket([]byte{0x45, 0x00}) // truncated IPv4
	controller.handlePacket([]byte{0x60, 0x00}) // truncated IPv6
	controller.handlePacket(buildIPv4Packet(net.ParseIP("100.86.0.1"), net.ParseIP("192.168.99.99"), []byte("unroutable")))

	// 2. Send packets from clientPeer -> readLoopClient -> tunPeer
	// Malformed/unknown packets are ignored without breaking the loop
	require.NoError(t, WriteMessage(clientPeer, []byte{0x10, 0x01})) // unknown version
	require.NoError(t, WriteMessage(clientPeer, []byte{0x45, 0x01})) // truncated IPv4
	require.NoError(t, WriteMessage(clientPeer, []byte{0x60, 0x01})) // truncated IPv6

	v4FromClient := buildIPv4Packet(net.ParseIP("10.20.1.2"), net.ParseIP("100.86.0.1"), []byte("pong-v4"))
	require.NoError(t, WriteMessage(clientPeer, v4FromClient))
	tunBuf := make([]byte, 1500)
	n, err := tunPeer.Read(tunBuf)
	require.NoError(t, err)
	require.Equal(t, v4FromClient, tunBuf[:n])

	v6FromClient := buildIPv6Packet(net.ParseIP("fd20::2"), net.ParseIP("fd00::1"), []byte("pong-v6"))
	require.NoError(t, WriteMessage(clientPeer, v6FromClient))
	n, err = tunPeer.Read(tunBuf)
	require.NoError(t, err)
	require.Equal(t, v6FromClient, tunBuf[:n])

	// Closing clientPeer causes readLoopClient to exit and remove its route
	_ = clientPeer.Close()
	require.Eventually(t, func() bool {
		_, err := controller.clientRouter.findConn(net.ParseIP("10.20.1.2"))
		return err != nil
	}, 2*time.Second, 10*time.Millisecond)

	// 3. Test Server connection read loop & dynamic source IP learning (IPv4 & IPv6)
	serverConn, serverPeer := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = serverPeer.Close()
	})
	closedCh := make(chan struct{})
	controller.StartServerConnReadLoop(context.Background(), serverConn, func() {
		close(closedCh)
	})

	// Malformed/unknown packets on serverPeer are discarded and not written to tunPeer
	require.NoError(t, WriteMessage(serverPeer, []byte{0x10, 0x01})) // unknown version
	require.NoError(t, WriteMessage(serverPeer, []byte{0x45, 0x01})) // truncated IPv4
	require.NoError(t, WriteMessage(serverPeer, []byte{0x60, 0x01})) // truncated IPv6

	v4FromServerPeer := buildIPv4Packet(net.ParseIP("172.16.0.10"), net.ParseIP("100.86.0.1"), []byte("srv-v4"))
	require.NoError(t, WriteMessage(serverPeer, v4FromServerPeer))
	n, err = tunPeer.Read(tunBuf)
	require.NoError(t, err)
	require.Equal(t, v4FromServerPeer, tunBuf[:n])

	// Sending a second packet from the same source IP exercises the fast-path in registerSrcIP
	require.NoError(t, WriteMessage(serverPeer, v4FromServerPeer))
	n, err = tunPeer.Read(tunBuf)
	require.NoError(t, err)
	require.Equal(t, v4FromServerPeer, tunBuf[:n])

	v6FromServerPeer := buildIPv6Packet(net.ParseIP("fd77::10"), net.ParseIP("fd00::1"), []byte("srv-v6"))
	require.NoError(t, WriteMessage(serverPeer, v6FromServerPeer))
	n, err = tunPeer.Read(tunBuf)
	require.NoError(t, err)
	require.Equal(t, v6FromServerPeer, tunBuf[:n])

	// Return traffic to 172.16.0.10 is now routed via serverRouter to serverPeer
	replyToServerPeer := buildIPv4Packet(net.ParseIP("100.86.0.1"), net.ParseIP("172.16.0.10"), []byte("reply-v4"))
	_, err = tunPeer.Write(replyToServerPeer)
	require.NoError(t, err)
	gotReply, err := ReadMessage(serverPeer)
	require.NoError(t, err)
	replyExpected := make([]byte, len(replyToServerPeer))
	copy(replyExpected, replyToServerPeer)
	replyExpected[8]--
	require.Equal(t, replyExpected, gotReply)

	// Closing serverPeer triggers cleanupConnIPs and onClose
	_ = serverPeer.Close()
	select {
	case <-closedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server readLoop onClose callback")
	}
	_, err = controller.serverRouter.findConnBySrc(net.ParseIP("172.16.0.10"))
	require.Error(t, err)

	// Stop controller and verify Run exits
	require.NoError(t, controller.Stop())
	select {
	case err := <-runErrCh:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Controller.Run to exit")
	}
}

type fakeTunDevice struct {
	readFn  func(bufs [][]byte, sizes []int, offset int) (int, error)
	writeFn func(bufs [][]byte, offset int) (int, error)
	mtuFn   func() (int, error)
	closed  bool
}

func (f *fakeTunDevice) File() *os.File { return nil }
func (f *fakeTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return f.readFn(bufs, sizes, offset)
}

func (f *fakeTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	return f.writeFn(bufs, offset)
}

func (f *fakeTunDevice) MTU() (int, error) {
	if f.mtuFn != nil {
		return f.mtuFn()
	}
	return defaultPacketSize, nil
}
func (f *fakeTunDevice) Name() (string, error)    { return "tun0", nil }
func (f *fakeTunDevice) Events() <-chan tun.Event { return nil }
func (f *fakeTunDevice) Close() error {
	f.closed = true
	return nil
}
func (f *fakeTunDevice) BatchSize() int { return 2 }

func TestTunDeviceWrapper(t *testing.T) {
	var writtenPayload []byte
	callCount := 0
	fake := &fakeTunDevice{
		mtuFn: func() (int, error) {
			return 0, errors.New("mtu error")
		},
		readFn: func(bufs [][]byte, sizes []int, off int) (int, error) {
			callCount++
			switch callCount {
			case 1:
				// Return batch of 2 packets
				sizes[0] = copy(bufs[0][off:], []byte("pkt-1"))
				sizes[1] = copy(bufs[1][off:], []byte("pkt-2"))
				return 2, nil
			case 2:
				// Return n=1 with size 0 (empty packet in batch)
				sizes[0] = 0
				return 1, nil
			case 3:
				// Return n=0 -> io.EOF
				return 0, nil
			default:
				return 0, errors.New("read failed")
			}
		},
		writeFn: func(bufs [][]byte, off int) (int, error) {
			writtenPayload = append([]byte(nil), bufs[0][off:]...)
			return 1, nil
		},
	}

	wrapper := newTunDeviceWrapper(fake)
	require.Equal(t, defaultPacketSize, wrapper.bufferSize)
	require.Len(t, wrapper.readBuffers, 2)

	buf := make([]byte, 64)
	n, err := wrapper.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pkt-1", string(buf[:n]))

	// Second read drains buffered second packet from batch without calling dev.Read
	n, err = wrapper.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "pkt-2", string(buf[:n]))

	// Third read gets empty batch entry -> 0, nil
	n, err = wrapper.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 0, n)

	// Fourth read gets n=0 -> io.EOF
	_, err = wrapper.Read(buf)
	require.ErrorIs(t, err, io.EOF)

	// Fifth read gets error
	_, err = wrapper.Read(buf)
	require.ErrorContains(t, err, "read failed")

	// Write copies payload at offset
	n, err = wrapper.Write([]byte("outbound-pkt"))
	require.NoError(t, err)
	require.Equal(t, len("outbound-pkt"), n)
	require.Equal(t, []byte("outbound-pkt"), writtenPayload)

	require.NoError(t, wrapper.Close())
	require.True(t, fake.closed)

	// Controller.Init and OpenTun reject invalid CIDR before attempting TUN creation
	badController := NewController(v1.VirtualNetConfig{Address: "invalid-cidr"})
	require.Error(t, badController.Init())
}
