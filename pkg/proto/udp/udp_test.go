package udp

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func TestUdpPacket(t *testing.T) {
	require := require.New(t)

	buf := []byte("hello world")
	udpMsg := NewUDPPacket(buf, nil, nil)

	newBuf, err := GetContent(udpMsg)
	require.NoError(err)
	require.EqualValues(buf, newBuf)
}

func TestForwardUserConnReturnsWhenSendChannelIsClosed(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	readCh := make(chan *msg.UDPPacket)
	sendCh := make(chan *msg.UDPPacket)
	close(sendCh)
	t.Cleanup(func() { close(readCh) })

	stopCh := make(chan struct{})
	t.Cleanup(func() { close(stopCh) })

	done := make(chan struct{})
	go func() {
		ForwardUserConn(listener, readCh, sendCh, stopCh, 1500)
		close(done)
	}()

	sender, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sender.Close() })

	_, err = sender.Write([]byte("trigger"))
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ForwardUserConn did not return after sending to a closed channel")
	}
}

// The stop channel ends the reader of the user connection. The caller
// cannot close readCh instead: the goroutine that sends on it would panic
// on a closed channel, and the panic is only contained by a recover.
func TestForwardUserConnStopsTheReaderOnTheStopChannel(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	// The user side of the flow: the forwarder writes the packets of
	// readCh to it.
	user, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = user.Close() })

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan *msg.UDPPacket, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	readerDone := make(chan struct{})
	go forwardUserConn(service, readCh, sendCh, stopCh, 1500, readerDone)

	readCh <- NewUDPPacket([]byte("before"), nil, user.LocalAddr().(*net.UDPAddr))

	buf := make([]byte, 64)
	require.NoError(user.SetReadDeadline(time.Now().Add(5 * time.Second)))
	n, _, err := user.ReadFromUDP(buf)
	require.NoError(err)
	require.Equal("before", string(buf[:n]))

	// The stop channel ends the reader of the forwarder.
	close(stopCh)
	select {
	case <-readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the reader of the forwarder did not stop")
	}

	readCh <- NewUDPPacket([]byte("after"), nil, user.LocalAddr().(*net.UDPAddr))

	require.NoError(user.SetReadDeadline(time.Now().Add(500 * time.Millisecond)))
	_, _, err = user.ReadFromUDP(buf)
	require.Error(err, "the reader of the forwarder was not stopped")
}

func TestForwardUserConnReturnsOnStopChannelWithoutUDPConnClose(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket)
	sendCh := make(chan *msg.UDPPacket)
	stopCh := make(chan struct{})

	done := make(chan struct{})
	go func() {
		ForwardUserConn(service, readCh, sendCh, stopCh, 1500)
		close(done)
	}()

	// Closing stopCh must cause ForwardUserConn to return without service.Close() being called
	close(stopCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardUserConn did not return when stopCh was closed")
	}
}

func TestForwardUserConnSkipsNilPacket(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	user, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = user.Close() })

	readCh := make(chan *msg.UDPPacket, 4)
	sendCh := make(chan *msg.UDPPacket, 4)
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(readCh)
		close(sendCh)
	})

	readerDone := make(chan struct{})
	done := make(chan struct{})
	go func() {
		forwardUserConn(service, readCh, sendCh, stopCh, 1500, readerDone)
		close(done)
	}()

	readCh <- nil
	readCh <- NewUDPPacket([]byte("after-nil"), nil, user.LocalAddr().(*net.UDPAddr))

	buf := make([]byte, 64)
	require.NoError(user.SetReadDeadline(time.Now().Add(3 * time.Second)))
	n, _, err := user.ReadFromUDP(buf)
	require.NoError(err)
	require.Equal("after-nil", string(buf[:n]))

	close(stopCh)
	select {
	case <-readerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the reader of ForwardUserConn did not stop")
	}
	_ = service.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ForwardUserConn did not return after closing udpConn")
	}
}

// The stop channel ends the reader of the forwarder. The caller cannot
// close readCh instead: the goroutine that sends on it would panic on a
// closed channel, and closing a channel while another goroutine sends on it
// is a data race that the race detector reports.
func TestForwarderStopsTheReaderOnTheStopChannel(t *testing.T) {
	require := require.New(t)

	// The local service of the flow: the forwarder writes the packets of
	// readCh to it.
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan msg.Message, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 1234}
	readCh <- NewUDPPacket([]byte("before"), nil, userAddr)

	buf := make([]byte, 64)
	require.NoError(service.SetReadDeadline(time.Now().Add(5 * time.Second)))
	n, fromAddr, err := service.ReadFromUDP(buf)
	require.NoError(err)
	require.Equal("before", string(buf[:n]))

	// The stop channel ends the reader of the forwarder and closes all active
	// flow sockets. Probing the ephemeral port confirms the stop branch ran.
	close(stopCh)
	require.Eventually(func() bool {
		probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: fromAddr.Port})
		if probeErr != nil {
			return false
		}
		_ = probe.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "the forwarder did not stop and close its flow socket")

	readCh <- NewUDPPacket([]byte("after"), nil, userAddr)

	require.NoError(service.SetReadDeadline(time.Now().Add(500 * time.Millisecond)))
	_, _, err = service.ReadFromUDP(buf)
	require.Error(err, "the reader of the forwarder was not stopped")
}

// When stopCh is closed, the forwarder must close all active flow sockets in
// udpConnMap immediately so ephemeral ports are not held open for the 30s idle timeout.
func TestForwarderClosesFlowSocketsOnStopChannel(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan msg.Message, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 1234}
	readCh <- NewUDPPacket([]byte("hello"), nil, userAddr)

	buf := make([]byte, 64)
	require.NoError(service.SetReadDeadline(time.Now().Add(5 * time.Second)))
	n, fromAddr, err := service.ReadFromUDP(buf)
	require.NoError(err)
	require.Equal("hello", string(buf[:n]))

	// Close stopCh. The forwarder must immediately close all active flow sockets
	// in udpConnMap rather than leaving them open for the 30-second idle timeout.
	close(stopCh)

	require.Eventually(func() bool {
		probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: fromAddr.Port})
		if probeErr != nil {
			return false
		}
		_ = probe.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "the flow socket was not closed immediately on stopCh")

	_, _ = service.WriteToUDP([]byte("late-reply"), fromAddr)

	select {
	case m := <-sendCh:
		t.Fatalf("unexpected packet forwarded after stopCh: %v", m)
	case <-time.After(300 * time.Millisecond):
	}
}

// The proxy protocol header describes the start of a UDP flow, so it must
// only be prepended to the first packet of a flow. Every later packet of the
// same flow is plain payload: a service that parses the header once would
// otherwise see the payload of every subsequent packet prefixed with a
// second header.
func TestForwarderSendsProxyProtocolHeaderOnlyOnFirstPacketOfFlow(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	received := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			received <- payload
		}
	}()

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan msg.Message, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 1234}
	Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "v1")

	readCh <- NewUDPPacket([]byte("first"), nil, userAddr)
	readCh <- NewUDPPacket([]byte("second"), nil, userAddr)

	var first, second []byte
	select {
	case first = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("the first packet was not delivered to the local service")
	}
	select {
	case second = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("the second packet was not delivered to the local service")
	}

	require.True(bytes.HasPrefix(first, []byte("PROXY ")),
		"the first packet of a flow must carry the proxy protocol header, got %q", first)
	require.Contains(string(first), "first")

	require.Equal([]byte("second"), second,
		"only the first packet of a flow may carry the proxy protocol header")
}

func TestForwarderSendsProxyProtocolHeaderPerPacket(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			require := require.New(t)

			service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(err)
			t.Cleanup(func() { _ = service.Close() })

			received := make(chan []byte, 8)
			go func() {
				buf := make([]byte, 2048)
				for {
					n, _, readErr := service.ReadFromUDP(buf)
					if readErr != nil {
						return
					}
					payload := make([]byte, n)
					copy(payload, buf[:n])
					received <- payload
				}
			}()

			readCh := make(chan *msg.UDPPacket, 8)
			sendCh := make(chan msg.Message, 8)
			stopCh := make(chan struct{})
			t.Cleanup(func() { close(readCh) })

			userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 1234}
			Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, version, "per-packet")

			readCh <- NewUDPPacket([]byte("first"), nil, userAddr)
			readCh <- NewUDPPacket([]byte("second"), nil, userAddr)

			var first, second []byte
			select {
			case first = <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("the first packet was not delivered to the local service")
			}
			select {
			case second = <-received:
			case <-time.After(5 * time.Second):
				t.Fatal("the second packet was not delivered to the local service")
			}

			// In per-packet mode, BOTH first and second packets carry the proxy protocol header.
			for _, pkt := range [][]byte{first, second} {
				rd := bufio.NewReader(bytes.NewReader(pkt))
				header, err := pp.Read(rd)
				require.NoError(err)
				if version == "v1" {
					require.Equal(byte(1), header.Version)
				} else {
					require.Equal(byte(2), header.Version)
					require.NotNil(header.SourceAddr)
					host, _, err := net.SplitHostPort(header.SourceAddr.String())
					require.NoError(err)
					require.Equal(userAddr.IP.String(), host)
				}
				rem, err := io.ReadAll(rd)
				require.NoError(err)
				require.True(string(rem) == "first" || string(rem) == "second")
			}
		})
	}
}

// serviceDatagram is a datagram that the local service of a test received.
type serviceDatagram struct {
	payload []byte
	from    *net.UDPAddr
}

// receiveServiceDatagram returns the next datagram the local service
// received.
func receiveServiceDatagram(t *testing.T, ch <-chan serviceDatagram) serviceDatagram {
	t.Helper()
	select {
	case d := <-ch:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("the local service did not receive the packet")
		return serviceDatagram{}
	}
}

// A udp flow that stays idle is retired: the socket towards the local
// service is closed and the flow is removed from the flow map, so the next
// packet of the same user starts a new flow on a new socket.
//
// A flow that keeps the socket of a retired flow leaks that socket and its
// file descriptor for the lifetime of the process, and a flow that keeps the
// map entry of a retired flow writes into a closed socket, which loses every
// packet of the user.
func TestForwarderRetiresIdleFlow(t *testing.T) {
	require := require.New(t)

	const idleTimeout = 300 * time.Millisecond

	// The local service: it records every datagram it receives together
	// with the address it came from, and echoes the payload back.
	receivedCh := make(chan serviceDatagram, 8)
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			receivedCh <- serviceDatagram{payload: payload, from: from}
			_, _ = service.WriteToUDP(payload, from)
		}
	}()

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan msg.Message, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 1234}
	forwarderWithIdleTimeout(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "v1", "", idleTimeout)

	// The first packet of a user opens the flow, so it carries the proxy
	// protocol header.
	readCh <- NewUDPPacket([]byte("first"), nil, userAddr)
	first := receiveServiceDatagram(t, receivedCh)
	require.True(bytes.HasPrefix(first.payload, []byte("PROXY ")),
		"the first packet of a flow must carry the proxy protocol header, got %q", first.payload)
	require.Contains(string(first.payload), "first")

	// The reply of the service travels back through the same flow.
	select {
	case raw := <-sendCh:
		require.IsType(&msg.UDPPacket{}, raw)
	case <-time.After(5 * time.Second):
		t.Fatal("the reply of the local service did not reach the user")
	}

	// A later packet of the same flow is plain payload: the header
	// describes the start of the flow.
	readCh <- NewUDPPacket([]byte("second"), nil, userAddr)
	second := receiveServiceDatagram(t, receivedCh)
	require.False(bytes.HasPrefix(second.payload, []byte("PROXY ")),
		"only the first packet of a flow may carry the proxy protocol header, got %q", second.payload)
	require.Equal([]byte("second"), second.payload)

	// The flow is idle now. Once the idle timeout expires, the socket
	// towards the service is closed, which releases the port it used.
	require.Eventually(func() bool {
		probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: first.from.Port})
		if probeErr != nil {
			return false
		}
		_ = probe.Close()
		return true
	}, 10*time.Second, 20*time.Millisecond,
		"the socket of the idle flow was not closed")

	// The retired flow was removed from the flow map as well, so the next
	// packet of the same user starts a new flow and carries the proxy
	// protocol header again.
	readCh <- NewUDPPacket([]byte("third"), nil, userAddr)
	third := receiveServiceDatagram(t, receivedCh)
	require.True(bytes.HasPrefix(third.payload, []byte("PROXY ")),
		"a packet that follows the retirement of a flow must start a new flow, got %q", third.payload)
	require.Contains(string(third.payload), "third")
}

// A socket that has already been replaced must not drop its replacement
// from the flow map: the flow would then open a second socket towards the
// local service for the same user while the first one is still alive, and
// the replies of the service would be split over both sockets.
func TestRemoveUDPConnDoesNotDropAReplacementSocket(t *testing.T) {
	require := require.New(t)

	var mu sync.RWMutex
	udpConnMap := make(map[string]*net.UDPConn)

	first := &net.UDPConn{}
	second := &net.UDPConn{}
	udpConnMap["user"] = first
	udpConnMap["user"] = second

	// The socket that was replaced cleans up after itself.
	removeUDPConn(udpConnMap, &mu, "user", first)

	current, ok := udpConnMap["user"]
	require.True(ok, "the replacement socket must still be registered")
	require.Same(second, current)

	// The owner of the entry removes it.
	removeUDPConn(udpConnMap, &mu, "user", second)
	_, ok = udpConnMap["user"]
	require.False(ok, "the socket must be removed by its owner")
}

func TestForwarderTProxySkipsNilRemoteAddr(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket, 4)
	sendCh := make(chan msg.Message, 4)
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(stopCh)
		close(readCh)
	})

	errCh := make(chan error, 1)
	Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "tproxy", ForwarderOptions{
		ProxyProtocol: "tproxy",
		OnError: func(err error, raddr net.Addr, dstAddr net.Addr) {
			errCh <- err
		},
	})

	readCh <- NewUDPPacket([]byte("should-drop"), nil, nil)

	select {
	case gotErr := <-errCh:
		require.Contains(gotErr.Error(), "non-nil remote address")
	case <-time.After(3 * time.Second):
		t.Fatal("expected OnError callback for nil RemoteAddr under tproxy")
	}

	require.NoError(service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
	buf := make([]byte, 64)
	_, _, readErr := service.ReadFromUDP(buf)
	require.Error(readErr, "service must not receive packet when RemoteAddr is nil under tproxy")
}

func TestForwarderProxyProtocolHeaderErrorSkipsWrite(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket, 4)
	sendCh := make(chan msg.Message, 4)
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(stopCh)
		close(readCh)
	})

	errCh := make(chan error, 1)
	Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "v1", ForwarderOptions{
		ProxyProtocol: "v1",
		OnError: func(err error, raddr net.Addr, dstAddr net.Addr) {
			errCh <- err
		},
	})

	// Empty IP on RemoteAddr causes BuildProxyProtocolHeader to return an error.
	userAddr := &net.UDPAddr{Port: 12345}
	readCh <- NewUDPPacket([]byte("must-not-send"), nil, userAddr)

	select {
	case gotErr := <-errCh:
		require.Error(gotErr)
	case <-time.After(3 * time.Second):
		t.Fatal("expected OnError callback when proxy protocol header build fails")
	}

	require.NoError(service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
	buf := make([]byte, 64)
	_, _, readErr := service.ReadFromUDP(buf)
	require.Error(readErr, "service must not receive raw payload when proxy protocol header build fails")
}

func TestForwarderWithDoneWaitsForAllFlowsOnStopChannel(t *testing.T) {
	require := require.New(t)

	receivedCh := make(chan serviceDatagram, 8)
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			receivedCh <- serviceDatagram{payload: payload, from: from}
			_, _ = service.WriteToUDP(payload, from)
		}
	}()

	readCh := make(chan *msg.UDPPacket, 8)
	sendCh := make(chan msg.Message, 8)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	user1 := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 10001}
	user2 := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 11), Port: 10002}
	readCh <- NewUDPPacket([]byte("one"), nil, user1)
	readCh <- NewUDPPacket([]byte("two"), nil, user2)

	d1 := receiveServiceDatagram(t, receivedCh)
	d2 := receiveServiceDatagram(t, receivedCh)

	// Drain both replies so both writerFn goroutines are actively running.
	for range 2 {
		select {
		case <-sendCh:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for service reply")
		}
	}

	close(stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForwarderWithDone did not close done after stopCh")
	}

	// All writerFn goroutines have exited before done closed, so closing sendCh
	// is race-free and panic-free even if the service sends late datagrams.
	close(sendCh)
	_, _ = service.WriteToUDP([]byte("late-1"), d1.from)
	_, _ = service.WriteToUDP([]byte("late-2"), d2.from)

	// Both flow sockets must already be closed by the time done closes.
	for _, addr := range []*net.UDPAddr{d1.from, d2.from} {
		probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addr.Port})
		require.NoError(probeErr, "flow socket %s should be closed before done closes", addr)
		_ = probe.Close()
	}
}

func TestForwarderWithDoneClosesOnReadChannelClose(t *testing.T) {
	require := require.New(t)

	receivedCh := make(chan serviceDatagram, 4)
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			receivedCh <- serviceDatagram{payload: payload, from: from}
		}
	}()

	readCh := make(chan *msg.UDPPacket, 4)
	sendCh := make(chan msg.Message, 4)
	stopCh := make(chan struct{})

	done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 12), Port: 10003}
	readCh <- NewUDPPacket([]byte("hello"), nil, userAddr)
	d := receiveServiceDatagram(t, receivedCh)

	// Closing readCh without closing stopCh should still tear down all flow sockets
	// and wait for writerFn goroutines before closing done.
	close(readCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForwarderWithDone did not close done after readCh closed")
	}

	close(sendCh)
	probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: d.from.Port})
	require.NoError(probeErr, "flow socket should be closed after readCh closes")
	_ = probe.Close()
}

func TestForwarderWithDoneClosesImmediatelyWithNoActiveFlows(t *testing.T) {
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = service.Close() })

	readCh := make(chan *msg.UDPPacket)
	sendCh := make(chan msg.Message)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	close(stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForwarderWithDone did not close done immediately with no active flows")
	}
	close(sendCh)
}

func TestForwarderWithDoneConcurrentFlowChurnAndIdleTimeout(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			_, _ = service.WriteToUDP(buf[:n], from)
		}
	}()

	readCh := make(chan *msg.UDPPacket, 64)
	sendCh := make(chan msg.Message, 64)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	done := forwarderWithIdleTimeout(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "", "", 15*time.Millisecond)

	// Drain sendCh concurrently until it is closed after <-done.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for m := range sendCh {
			_ = m
		}
	}()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for i := range 60 {
		userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, byte(20+(i%15))), Port: 20000 + (i % 15)}
		readCh <- NewUDPPacket([]byte("ping"), nil, userAddr)
		if i%10 == 0 {
			<-ticker.C
		}
	}

	close(stopCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForwarderWithDone did not close done under flow churn")
	}

	// Closing sendCh immediately after <-done must not panic or race.
	close(sendCh)
	select {
	case <-drainDone:
	case <-time.After(5 * time.Second):
		t.Fatal("drain goroutine did not exit after sendCh closed")
	}
}

func TestForwarderSkipsNilRemoteAddrNonTProxy(t *testing.T) {
	for _, ppVersion := range []string{"", "v1", "v2"} {
		t.Run("pp="+ppVersion, func(t *testing.T) {
			require := require.New(t)

			service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(err)
			t.Cleanup(func() { _ = service.Close() })

			readCh := make(chan *msg.UDPPacket, 4)
			sendCh := make(chan msg.Message, 4)
			stopCh := make(chan struct{})
			t.Cleanup(func() {
				close(stopCh)
				close(readCh)
			})

			errCh := make(chan error, 1)
			Forwarder(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, ppVersion, ForwarderOptions{
				ProxyProtocol: ppVersion,
				OnError: func(err error, raddr net.Addr, dstAddr net.Addr) {
					errCh <- err
				},
			})

			readCh <- nil
			readCh <- NewUDPPacket([]byte("should-drop"), nil, nil)

			select {
			case gotErr := <-errCh:
				require.Contains(gotErr.Error(), "non-nil remote address")
			case <-time.After(3 * time.Second):
				t.Fatal("expected OnError callback for nil RemoteAddr")
			}

			require.NoError(service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
			buf := make([]byte, 64)
			_, _, readErr := service.ReadFromUDP(buf)
			require.Error(readErr, "service must not receive packet when RemoteAddr is nil")
		})
	}

	t.Run("OnError_nil", func(t *testing.T) {
		require := require.New(t)

		service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(err)
		t.Cleanup(func() { _ = service.Close() })

		readCh := make(chan *msg.UDPPacket, 4)
		sendCh := make(chan msg.Message, 4)
		stopCh := make(chan struct{})

		done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")
		readCh <- nil
		readCh <- NewUDPPacket([]byte("should-drop"), nil, nil)

		require.NoError(service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
		buf := make([]byte, 64)
		_, _, readErr := service.ReadFromUDP(buf)
		require.Error(readErr, "service must not receive packet when RemoteAddr is nil")

		close(stopCh)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("ForwarderWithDone did not close done after stopCh")
		}
		close(readCh)
		close(sendCh)
	})
}

func TestForwarderWriterReturnsWhenSendChannelIsClosed(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	clientAddrCh := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 2048)
		n, from, readErr := service.ReadFromUDP(buf)
		if readErr != nil {
			return
		}
		_, _ = service.WriteToUDP(buf[:n], from)
		clientAddrCh <- from
	}()

	readCh := make(chan *msg.UDPPacket, 4)
	sendCh := make(chan msg.Message)
	close(sendCh)
	stopCh := make(chan struct{})
	t.Cleanup(func() { close(readCh) })

	done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, "")

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 30), Port: 12345}
	readCh <- NewUDPPacket([]byte("trigger"), nil, userAddr)

	var clientAddr *net.UDPAddr
	select {
	case clientAddr = <-clientAddrCh:
	case <-time.After(3 * time.Second):
		t.Fatal("service did not receive packet and send reply")
	}

	// Verify writerFn exits and closes its flow socket on closed sendCh before stopCh is closed.
	require.Eventually(func() bool {
		probe, probeErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: clientAddr.Port})
		if probeErr != nil {
			return false
		}
		_ = probe.Close()
		return true
	}, 3*time.Second, 10*time.Millisecond, "writerFn did not exit and close flow socket after sending on closed sendCh")

	close(stopCh)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ForwarderWithDone did not close done after stopCh")
	}
}

func TestForwarderProxyProtocolPerPacketPoolReuse(t *testing.T) {
	require := require.New(t)

	receivedCh := make(chan serviceDatagram, 16)
	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			payload := make([]byte, n)
			copy(payload, buf[:n])
			receivedCh <- serviceDatagram{payload: payload, from: from}
		}
	}()

	readCh := make(chan *msg.UDPPacket, 16)
	sendCh := make(chan msg.Message, 16)
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(readCh)
		close(sendCh)
	})

	done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 2048, "v2", ForwarderOptions{
		ProxyProtocol:     "v2",
		ProxyProtocolMode: "per-packet",
	})

	userAddr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 44), Port: 54321}
	dstAddr := service.LocalAddr().(*net.UDPAddr)
	expectedHeader, err := netpkg.BuildProxyProtocolHeader(userAddr, dstAddr, "v2")
	require.NoError(err)

	sizes := []int{10, 1400, 32, 1400, 5}
	for i, sz := range sizes {
		payload := make([]byte, sz)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		readCh <- NewUDPPacket(payload, nil, userAddr)

		d := receiveServiceDatagram(t, receivedCh)
		require.Len(d.payload, len(expectedHeader)+sz)
		require.Equal(expectedHeader, d.payload[:len(expectedHeader)])
		require.Equal(payload, d.payload[len(expectedHeader):])
	}

	close(stopCh)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("ForwarderWithDone did not close done after stopCh")
	}
}

func TestForwarderProxyProtocolHeaderErrorDoesNotLeaveStaleFlow(t *testing.T) {
	for _, ppVersion := range []string{"v1", "v2"} {
		t.Run(ppVersion, func(t *testing.T) {
			require := require.New(t)

			service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(err)
			t.Cleanup(func() { _ = service.Close() })

			readCh := make(chan *msg.UDPPacket, 4)
			sendCh := make(chan msg.Message, 4)
			stopCh := make(chan struct{})
			t.Cleanup(func() {
				close(readCh)
				close(sendCh)
			})

			errCh := make(chan error, 4)
			done := ForwarderWithDone(service.LocalAddr().(*net.UDPAddr), readCh, sendCh, stopCh, 1500, ppVersion, ForwarderOptions{
				ProxyProtocol: ppVersion,
				OnError: func(err error, raddr net.Addr, dstAddr net.Addr) {
					errCh <- err
				},
			})

			// UDPAddr with nil IP passes RemoteAddr != nil check, but causes BuildProxyProtocolHeader to fail.
			badAddr := &net.UDPAddr{Port: 1234}

			// First packet: must fail header construction and not register a stale flow.
			readCh <- NewUDPPacket([]byte("first-bad"), nil, badAddr)
			select {
			case gotErr := <-errCh:
				require.Contains(gotErr.Error(), "invalid proxy protocol version or addresses")
			case <-time.After(3 * time.Second):
				t.Fatal("expected OnError for first packet with nil RemoteAddr.IP")
			}

			// Second packet for the same RemoteAddr: if a stale flow were left in udpConnMap,
			// first-packet mode would treat it as an existing flow, skip BuildProxyProtocolHeader,
			// and forward the raw payload to service without a Proxy Protocol header.
			readCh <- NewUDPPacket([]byte("second-bad"), nil, badAddr)
			select {
			case gotErr := <-errCh:
				require.Contains(gotErr.Error(), "invalid proxy protocol version or addresses")
			case <-time.After(3 * time.Second):
				t.Fatal("expected OnError for second packet; stale flow may have been left in udpConnMap")
			}

			require.NoError(service.SetReadDeadline(time.Now().Add(150 * time.Millisecond)))
			buf := make([]byte, 64)
			_, _, readErr := service.ReadFromUDP(buf)
			require.Error(readErr, "service must not receive any packet when BuildProxyProtocolHeader fails")

			close(stopCh)
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("ForwarderWithDone did not close done after stopCh")
			}
		})
	}
}

func TestForwarderWithOptions_MaxFlowsEvictsLRU_CANON070(t *testing.T) {
	require := require.New(t)

	service, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(err)
	t.Cleanup(func() { _ = service.Close() })

	receivedPackets := make(chan string, 16)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, _, readErr := service.ReadFromUDP(buf)
			if readErr != nil {
				return
			}
			receivedPackets <- string(buf[:n])
		}
	}()

	readCh := make(chan *msg.UDPPacket, 16)
	sendCh := make(chan msg.Message, 16)
	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(readCh)
	})

	// Run forwarderWithOptions with MaxFlows: 2
	done := forwarderWithOptions(
		service.LocalAddr().(*net.UDPAddr),
		readCh,
		sendCh,
		stopCh,
		1500,
		ForwarderOptions{MaxFlows: 2},
		10*time.Second,
	)

	user1 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 10001}
	user2 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 10002}
	user3 := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 3), Port: 10003}

	// 1. Send packet from user1
	readCh <- NewUDPPacket([]byte("msg-from-user1"), nil, user1)
	select {
	case msg := <-receivedPackets:
		require.Equal("msg-from-user1", msg)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for user1 packet")
	}

	// 2. Send packet from user2 (table now holds user1 and user2)
	readCh <- NewUDPPacket([]byte("msg-from-user2"), nil, user2)
	select {
	case msg := <-receivedPackets:
		require.Equal("msg-from-user2", msg)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for user2 packet")
	}

	// 3. Touch user1 again so user1 becomes MRU and user2 becomes LRU
	readCh <- NewUDPPacket([]byte("msg2-from-user1"), nil, user1)
	select {
	case msg := <-receivedPackets:
		require.Equal("msg2-from-user1", msg)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for user1 second packet")
	}

	// 4. Send packet from user3. Since MaxFlows is 2, user2 (LRU) must be evicted
	readCh <- NewUDPPacket([]byte("msg-from-user3"), nil, user3)
	select {
	case msg := <-receivedPackets:
		require.Equal("msg-from-user3", msg)
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for user3 packet")
	}

	close(stopCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder did not exit cleanly")
	}
}
