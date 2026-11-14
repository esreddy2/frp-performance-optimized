// Copyright 2017 fatedier, fatedier@gmail.com
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

package udp

import (
	"container/list"
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/fatedier/golib/pool"

	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func NewUDPPacket(buf []byte, laddr, raddr *net.UDPAddr) *msg.UDPPacket {
	content := make([]byte, len(buf))
	copy(content, buf)
	return &msg.UDPPacket{
		Content:    content,
		LocalAddr:  laddr,
		RemoteAddr: raddr,
	}
}

func GetContent(m *msg.UDPPacket) (buf []byte, err error) {
	return m.Content, nil
}

// ForwardUserConn forwards the packets of readCh to udpConn and the replies
// of udpConn to sendCh.
//
// The function returns when the connection fails or when stopCh is closed.
// The caller must not close readCh or sendCh while the function is running: a
// send on a closed channel panics, and the goroutine that sends is not always
// able to recover from it. The stop channel ends the function instead.
func ForwardUserConn(udpConn *net.UDPConn, readCh <-chan *msg.UDPPacket, sendCh chan<- *msg.UDPPacket, stopCh <-chan struct{}, bufSize int) {
	forwardUserConn(udpConn, readCh, sendCh, stopCh, bufSize, nil)
}

func forwardUserConn(
	udpConn *net.UDPConn,
	readCh <-chan *msg.UDPPacket,
	sendCh chan<- *msg.UDPPacket,
	stopCh <-chan struct{},
	bufSize int,
	readerDone chan<- struct{},
) {
	// read
	go func() {
		if readerDone != nil {
			defer close(readerDone)
		}
		for {
			select {
			case udpMsg, ok := <-readCh:
				if !ok {
					return
				}
				if udpMsg == nil {
					continue
				}
				buf, err := GetContent(udpMsg)
				if err != nil {
					continue
				}
				_, _ = udpConn.WriteToUDP(buf, udpMsg.RemoteAddr)
			case <-stopCh:
				return
			}
		}
	}()

	// write
	buf := pool.GetBuf(bufSize)
	defer pool.PutBuf(buf)

	stopWait := make(chan struct{})
	defer close(stopWait)
	go func() {
		select {
		case <-stopCh:
			_ = udpConn.SetReadDeadline(time.Now())
		case <-stopWait:
		}
	}()

	// Wrap the write loop in a function that recovers from send-on-closed-channel panic.
	func() {
		defer func() {
			_ = recover() // Ignore panic from send on closed channel; function returns
		}()
		for {
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// NewUDPPacket copies buf[:n], so the read buffer can be reused
			udpMsg := NewUDPPacket(buf[:n], nil, remoteAddr)

			select {
			case sendCh <- udpMsg:
			default:
				// Channel full, drop packet
			}
		}
	}()
}

// udpSocketIdleTimeout bounds how long a udp socket towards the local
// service may stay silent before it is closed and the flow is restarted on a
// new socket.
const udpSocketIdleTimeout = 30 * time.Second

// defaultMaxFlows is the maximum number of concurrent UDP flow sockets maintained
// in the forwarder flow table before oldest/LRU sockets are evicted.
const defaultMaxFlows = 1024

// removeUDPConn drops conn from the flow map, but only when it is still the
// socket registered for addr. A socket that has already been replaced must
// not drop its replacement from the map: the flow would then start a second
// socket for the same user while the first one is still alive.
func removeUDPConn(udpConnMap map[string]*net.UDPConn, mu *sync.RWMutex, addr string, conn *net.UDPConn) {
	removeUDPConnWithLRU(udpConnMap, nil, nil, mu, addr, conn)
}

func removeUDPConnWithLRU(
	udpConnMap map[string]*net.UDPConn,
	flowOrder map[string]*list.Element,
	lruList *list.List,
	mu *sync.RWMutex,
	addr string,
	conn *net.UDPConn,
) {
	mu.Lock()
	defer mu.Unlock()
	if current, ok := udpConnMap[addr]; ok && current == conn {
		delete(udpConnMap, addr)
		if flowOrder != nil && lruList != nil {
			if elem, exists := flowOrder[addr]; exists {
				lruList.Remove(elem)
				delete(flowOrder, addr)
			}
		}
	}
}

// Forwarder forwards the packets of readCh to the local service at dstAddr
// and the replies of the service back to sendCh.
//
// The function returns when the connection fails or when stopCh is closed.
// The caller must not close readCh or sendCh while the function is running: a
// send on a closed channel panics, and the goroutine that sends is not always
// able to recover from it. Closing a channel while another goroutine sends on
// it is a data race as well: the runtime records a send as a read of the
// channel and a close as a write of it. The stop channel ends the goroutines
// that use the channels instead.

// ForwarderOptions configures options for Forwarder.
type ForwarderOptions struct {
	Context           context.Context
	ProxyProtocol     string
	ProxyProtocolMode string
	SocketMark        int
	MaxFlows          int
	OnError           func(err error, raddr net.Addr, dstAddr net.Addr)
}

// Forwarder forwards UDP packets between the local service and work connections.
// It creates a socket to the local service for each user address that sends a
// packet, and it tears the socket down when the user goes idle.
//
// In addition to proxyProtocol, optional extra arguments can be passed:
// - string: sets ProxyProtocolMode ("first-packet" or "per-packet")
// - ForwarderOptions / *ForwarderOptions: sets full options including SocketMark
func Forwarder(
	dstAddr *net.UDPAddr,
	readCh <-chan *msg.UDPPacket,
	sendCh chan<- msg.Message,
	stopCh <-chan struct{},
	bufSize int,
	proxyProtocol string,
	extra ...any,
) {
	_ = ForwarderWithDone(dstAddr, readCh, sendCh, stopCh, bufSize, proxyProtocol, extra...)
}

// ForwarderWithDone is like Forwarder, but returns a channel that is closed
// after the forwarder's reader and all per-flow writer goroutines have exited.
func ForwarderWithDone(
	dstAddr *net.UDPAddr,
	readCh <-chan *msg.UDPPacket,
	sendCh chan<- msg.Message,
	stopCh <-chan struct{},
	bufSize int,
	proxyProtocol string,
	extra ...any,
) <-chan struct{} {
	opts := ForwarderOptions{
		ProxyProtocol: proxyProtocol,
	}
	for _, arg := range extra {
		switch v := arg.(type) {
		case string:
			opts.ProxyProtocolMode = v
		case ForwarderOptions:
			opts = v
		case *ForwarderOptions:
			if v != nil {
				opts = *v
			}
		}
	}
	if opts.ProxyProtocol == "" {
		opts.ProxyProtocol = proxyProtocol
	}
	return forwarderWithOptions(dstAddr, readCh, sendCh, stopCh, bufSize, opts, udpSocketIdleTimeout)
}

// forwarderWithIdleTimeout is Forwarder with a configurable idle timeout, so
// that the retirement of an idle flow can be exercised without waiting for
// the production timeout.
func forwarderWithIdleTimeout(
	dstAddr *net.UDPAddr,
	readCh <-chan *msg.UDPPacket,
	sendCh chan<- msg.Message,
	stopCh <-chan struct{},
	bufSize int,
	proxyProtocol string,
	proxyProtocolMode string,
	idleTimeout time.Duration,
) <-chan struct{} {
	return forwarderWithOptions(dstAddr, readCh, sendCh, stopCh, bufSize, ForwarderOptions{
		ProxyProtocol:     proxyProtocol,
		ProxyProtocolMode: proxyProtocolMode,
	}, idleTimeout)
}

func forwarderWithOptions(
	dstAddr *net.UDPAddr,
	readCh <-chan *msg.UDPPacket,
	sendCh chan<- msg.Message,
	stopCh <-chan struct{},
	bufSize int,
	options ForwarderOptions,
	idleTimeout time.Duration,
) <-chan struct{} {
	done := make(chan struct{})
	var mu sync.RWMutex
	udpConnMap := make(map[string]*net.UDPConn)
	flowOrder := make(map[string]*list.Element)
	lruList := list.New()
	var writerWg sync.WaitGroup

	maxFlows := options.MaxFlows
	if maxFlows <= 0 {
		maxFlows = defaultMaxFlows
	}

	closeAllConns := func() {
		mu.Lock()
		for _, conn := range udpConnMap {
			_ = conn.Close()
		}
		clear(udpConnMap)
		clear(flowOrder)
		lruList.Init()
		mu.Unlock()
	}

	// read from dstAddr and write to sendCh
	writerFn := func(raddr *net.UDPAddr, udpConn *net.UDPConn) {
		defer writerWg.Done()
		addr := raddr.String()
		defer func() {
			removeUDPConnWithLRU(udpConnMap, flowOrder, lruList, &mu, addr, udpConn)
			udpConn.Close()
		}()

		buf := pool.GetBuf(bufSize)
		defer pool.PutBuf(buf)
		// The read deadline is an idle timeout: it is pushed forward while
		// packets keep arriving, so a flow whose service pushes data without
		// the user sending anything is not torn down. Arming the deadline only
		// once would expire it even on a socket that keeps receiving packets.
		deadline := netpkg.NewIdleReadDeadline(udpConn, idleTimeout)

		// Wrap the write loop in a function that recovers from send-on-closed-channel panic.
		func() {
			defer func() {
				_ = recover() // Ignore panic from send on closed channel; function returns
			}()
			for {
				n, _, err := udpConn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = deadline.Refresh()

				udpMsg := NewUDPPacket(buf[:n], nil, raddr)

				// The stop channel is checked before the send, so that the
				// flow of a retired work connection ends with the first
				// packet of the service instead of with a random choice
				// between the send and the stop.
				select {
				case <-stopCh:
					return
				default:
				}
				select {
				case sendCh <- udpMsg:
				default:
					// Channel full, drop packet
				}
			}
		}()
	}

	// read from readCh
	go func() {
		defer close(done)
		defer writerWg.Wait()
		defer closeAllConns()

		for {
			select {
			case udpMsg, ok := <-readCh:
				if !ok {
					return
				}
				if udpMsg == nil {
					continue
				}
				buf, err := GetContent(udpMsg)
				if err != nil {
					continue
				}

				if udpMsg.RemoteAddr == nil {
					if options.OnError != nil {
						if options.ProxyProtocol == "tproxy" {
							options.OnError(errors.New("transparent proxy requires non-nil remote address"), nil, dstAddr)
						} else {
							options.OnError(errors.New("udp packet requires non-nil remote address"), nil, dstAddr)
						}
					}
					continue
				}

				addrStr := udpMsg.RemoteAddr.String()
				mu.Lock()
				udpConn, ok := udpConnMap[addrStr]
				if ok {
					if elem, hasElem := flowOrder[addrStr]; hasElem {
						lruList.MoveToFront(elem)
					}
				}
				mu.Unlock()

				// Build the proxy protocol header before creating/registering a new flow
				// so a header-construction failure does not leave a stale flow in udpConnMap.
				// By default ("first-packet"), only the first packet of a new flow carries the header.
				// In "per-packet" mode, every UDP datagram carries the header (required by HAProxy/NGINX).
				shouldAddProxyProtocol := (options.ProxyProtocol == "v1" || options.ProxyProtocol == "v2") &&
					(!ok || options.ProxyProtocolMode == "per-packet")

				var ppBuf []byte
				if shouldAddProxyProtocol {
					var err error
					ppBuf, err = netpkg.BuildProxyProtocolHeader(udpMsg.RemoteAddr, dstAddr, options.ProxyProtocol)
					if err != nil {
						if options.OnError != nil {
							options.OnError(err, udpMsg.RemoteAddr, dstAddr)
						}
						continue
					}
				}

				if !ok {
					// Dial outside the lock to avoid blocking other readers/writers.
					var err error
					if options.ProxyProtocol == "tproxy" {
						dialCtx := options.Context
						if dialCtx == nil {
							dialCtx = context.Background()
						}
						udpConn, err = netpkg.DialUDPTransparent(dialCtx, udpMsg.RemoteAddr, dstAddr, options.SocketMark)
					} else {
						udpConn, err = net.DialUDP("udp", nil, dstAddr)
					}
					if err != nil {
						if options.OnError != nil {
							options.OnError(err, udpMsg.RemoteAddr, dstAddr)
						}
						continue
					}

					isNewFlow := false
					mu.Lock()
					// Double-check after acquiring write lock.
					if existing, exists := udpConnMap[addrStr]; exists {
						_ = udpConn.Close()
						udpConn = existing
						if elem, hasElem := flowOrder[addrStr]; hasElem {
							lruList.MoveToFront(elem)
						}
					} else {
						// Flow table capacity check: evict LRU flow if table is full
						for len(udpConnMap) >= maxFlows {
							oldestElem := lruList.Back()
							if oldestElem == nil {
								break
							}
							oldestAddr := oldestElem.Value.(string)
							lruList.Remove(oldestElem)
							delete(flowOrder, oldestAddr)
							if oldConn, hasOld := udpConnMap[oldestAddr]; hasOld {
								delete(udpConnMap, oldestAddr)
								_ = oldConn.Close()
							}
						}

						elem := lruList.PushFront(addrStr)
						flowOrder[addrStr] = elem
						udpConnMap[addrStr] = udpConn
						isNewFlow = true
					}
					mu.Unlock()

					if isNewFlow {
						writerWg.Add(1)
						go writerFn(udpMsg.RemoteAddr, udpConn)
					}
				}

				var ppBufPtr *[]byte
				var finalBuf []byte
				if shouldAddProxyProtocol {
					// Prepend proxy protocol header to the UDP payload
					ppBufPtr = ppBufPool.Get().(*[]byte)
					finalBuf = *ppBufPtr
					if cap(finalBuf) < len(ppBuf)+len(buf) {
						finalBuf = make([]byte, len(ppBuf)+len(buf))
					} else {
						finalBuf = finalBuf[:len(ppBuf)+len(buf)]
					}
					copy(finalBuf, ppBuf)
					copy(finalBuf[len(ppBuf):], buf)
					buf = finalBuf
				}

				_, err = udpConn.Write(buf)
				if ppBufPtr != nil {
					*ppBufPtr = finalBuf[:0]
					ppBufPool.Put(ppBufPtr)
				}
				if err != nil {
					udpConn.Close()
					removeUDPConnWithLRU(udpConnMap, flowOrder, lruList, &mu, addrStr, udpConn)
				} else {
					// Reset the idle deadline only when a write succeeds. Doing this
					// per packet is fine here because writes are relatively infrequent
					// compared to reads, and it keeps the socket from being closed
					// during a burst of incoming traffic.
					_ = udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
				}
			case <-stopCh:
				return
			}
		}
	}()

	return done
}

var ppBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1024)
		return &b
	},
}
