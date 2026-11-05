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

package net

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/golib/pool"
)

type UDPPacket struct {
	Buf        []byte
	LocalAddr  net.Addr
	RemoteAddr net.Addr
}

type FakeUDPConn struct {
	l *UDPListener

	localAddr  net.Addr
	remoteAddr net.Addr
	packets    chan []byte
	closeFlag  bool

	lastActive time.Time
	mu         sync.RWMutex

	accepted bool
	notified bool

	idleMu    sync.Mutex
	idleTimer *time.Timer
}

func NewFakeUDPConn(l *UDPListener, laddr, raddr net.Addr) *FakeUDPConn {
	fc := &FakeUDPConn{
		l:          l,
		localAddr:  laddr,
		remoteAddr: raddr,
		packets:    make(chan []byte, 20),
	}
	fc.lastActive = time.Now()
	fc.resetIdleTimer()
	return fc
}

func (c *FakeUDPConn) resetIdleTimer() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idleTimer != nil {
		c.idleTimer.Stop()
	}
	c.idleTimer = time.AfterFunc(10*time.Second, func() {
		c.Close()
	})
}

func (c *FakeUDPConn) stopIdleTimer() {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if c.idleTimer != nil {
		c.idleTimer.Stop()
		c.idleTimer = nil
	}
}

func (c *FakeUDPConn) touch() {
	c.mu.Lock()
	if c.closeFlag {
		c.mu.Unlock()
		return
	}
	c.lastActive = time.Now()
	c.mu.Unlock()
	c.resetIdleTimer()
}

func (c *FakeUDPConn) putPacket(content []byte) {
	c.mu.RLock()
	closed := c.closeFlag
	c.mu.RUnlock()
	if closed {
		pool.PutBuf(content)
		return
	}

	defer func() {
		if r := recover(); r != nil {
			pool.PutBuf(content)
		}
	}()

	select {
	case c.packets <- content:
	default:
		pool.PutBuf(content)
	}
}

func (c *FakeUDPConn) Read(b []byte) (n int, err error) {
	content, ok := <-c.packets
	if !ok {
		return 0, io.EOF
	}
	c.touch()

	n = min(len(b), len(content))
	copy(b, content)
	pool.PutBuf(content)
	return n, nil
}

func (c *FakeUDPConn) Write(b []byte) (n int, err error) {
	c.mu.RLock()
	if c.closeFlag {
		c.mu.RUnlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.RUnlock()

	buf := pool.GetBuf(len(b))
	copy(buf, b)

	packet := &UDPPacket{
		Buf:        buf,
		LocalAddr:  c.localAddr,
		RemoteAddr: c.remoteAddr,
	}
	if err := c.l.writeUDPPacket(packet); err != nil {
		pool.PutBuf(buf)
		return 0, err
	}

	c.touch()
	return len(b), nil
}

func (c *FakeUDPConn) Close() error {
	c.mu.Lock()
	if !c.closeFlag {
		c.closeFlag = true
		func() {
			defer func() {
				_ = recover()
			}()
			close(c.packets)
		}()
	}
	c.mu.Unlock()

	c.stopIdleTimer()

	if c.l != nil {
		c.l.mu.Lock()
		delete(c.l.fakeConns, c.remoteAddr.String())
		c.l.mu.Unlock()
	}
	return nil
}

func (c *FakeUDPConn) IsClosed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.closeFlag
}

func (c *FakeUDPConn) IsAccepted() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accepted
}

func (c *FakeUDPConn) isNotified() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.notified
}

func (c *FakeUDPConn) setNotified(v bool) {
	c.mu.Lock()
	c.notified = v
	c.mu.Unlock()
}

func (c *FakeUDPConn) markAccepted() {
	c.mu.Lock()
	c.accepted = true
	c.mu.Unlock()
}

func (c *FakeUDPConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *FakeUDPConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *FakeUDPConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *FakeUDPConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *FakeUDPConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type UDPListener struct {
	addr      net.Addr
	acceptCh  chan net.Conn
	writeCh   chan *UDPPacket
	readConn  net.Conn
	closeFlag bool
	mu        sync.Mutex
	closeOnce sync.Once

	fakeConns map[string]*FakeUDPConn
}

func ListenUDP(bindAddr string, bindPort int) (l *UDPListener, err error) {
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindAddr, strconv.Itoa(bindPort)))
	if err != nil {
		return l, err
	}
	readConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return l, err
	}

	l = &UDPListener{
		addr:      udpAddr,
		acceptCh:  make(chan net.Conn, 1024),
		writeCh:   make(chan *UDPPacket, 1000),
		readConn:  readConn,
		fakeConns: make(map[string]*FakeUDPConn),
	}

	// for reading
	go func() {
		for {
			buf := pool.GetBuf(1450)
			n, remoteAddr, err := readConn.ReadFromUDP(buf)
			if err != nil {
				pool.PutBuf(buf)
				l.mu.Lock()
				if !l.closeFlag {
					l.closeFlag = true
				}
				l.mu.Unlock()
				l.closeChannels()
				return
			}

			l.mu.Lock()
			if l.closeFlag {
				l.mu.Unlock()
				pool.PutBuf(buf)
				continue
			}
			fakeConn, exist := l.fakeConns[remoteAddr.String()]
			if !exist || fakeConn.IsClosed() {
				fakeConn = NewFakeUDPConn(l, l.Addr(), remoteAddr)
				l.fakeConns[remoteAddr.String()] = fakeConn
			}
			l.mu.Unlock()

			fakeConn.putPacket(buf[:n])

			if !fakeConn.IsAccepted() && !fakeConn.isNotified() {
				select {
				case l.acceptCh <- fakeConn:
					fakeConn.setNotified(true)
				default:
				}
			}
		}
	}()

	// for writing
	go func() {
		for {
			packet, ok := <-l.writeCh
			if !ok {
				return
			}

			if addr, ok := packet.RemoteAddr.(*net.UDPAddr); ok {
				if _, err := readConn.WriteToUDP(packet.Buf, addr); err != nil {
					pool.PutBuf(packet.Buf)
					return
				}
			}
			pool.PutBuf(packet.Buf)
		}
	}()

	return
}

func (l *UDPListener) writeUDPPacket(packet *UDPPacket) (err error) {
	defer func() {
		if errRet := recover(); errRet != nil {
			err = fmt.Errorf("udp write closed listener")
		}
	}()
	l.writeCh <- packet
	return
}

func (l *UDPListener) WriteMsg(buf []byte, remoteAddr *net.UDPAddr) (err error) {
	// only set remote addr here
	packetBuf := pool.GetBuf(len(buf))
	copy(packetBuf, buf)
	packet := &UDPPacket{
		Buf:        packetBuf,
		RemoteAddr: remoteAddr,
	}
	if err = l.writeUDPPacket(packet); err != nil {
		pool.PutBuf(packetBuf)
	}
	return
}

func (l *UDPListener) Accept() (net.Conn, error) {
	conn, ok := <-l.acceptCh
	if !ok {
		return nil, fmt.Errorf("channel for udp listener closed")
	}
	if fc, ok := conn.(*FakeUDPConn); ok {
		fc.markAccepted()
	}
	return conn, nil
}

func (l *UDPListener) closeChannels() {
	l.closeOnce.Do(func() {
		close(l.acceptCh)
		close(l.writeCh)
	})
}

func (l *UDPListener) Close() error {
	l.mu.Lock()
	if l.closeFlag {
		l.mu.Unlock()
		return nil
	}
	l.closeFlag = true
	conns := make([]*FakeUDPConn, 0, len(l.fakeConns))
	for _, fc := range l.fakeConns {
		conns = append(conns, fc)
	}
	l.fakeConns = make(map[string]*FakeUDPConn)
	readConn := l.readConn
	l.mu.Unlock()

	for _, fc := range conns {
		_ = fc.Close()
	}
	if readConn != nil {
		readConn.Close()
	}
	l.closeChannels()
	return nil
}

func (l *UDPListener) Addr() net.Addr {
	return l.addr
}

// ConnectedUDPConn is a wrapper for net.UDPConn which converts WriteTo syscalls
// to Write syscalls that are 4 times faster on some OS'es. This should only be
// used for connections that were produced by a net.Dial* call.
type ConnectedUDPConn struct{ *net.UDPConn }

// WriteTo redirects all writes to the Write syscall, which is 4 times faster.
func (c *ConnectedUDPConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }
