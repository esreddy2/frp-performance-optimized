// Copyright 2023 The frp Authors
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

package msg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/proto/wire"
)

var ErrSendQueueFull = errors.New("dispatcher send queue is full")

type ReadWriter interface {
	ReadMsg() (Message, error)
	ReadMsgInto(Message) error
	WriteMsg(Message) error
}

type Conn struct {
	net.Conn
	rw ReadWriter
}

func NewConn(conn net.Conn, rw ReadWriter) *Conn {
	return &Conn{
		Conn: conn,
		rw:   rw,
	}
}

func (c *Conn) ReadMsg() (Message, error) {
	return c.rw.ReadMsg()
}

func (c *Conn) ReadMsgInto(m Message) error {
	return c.rw.ReadMsgInto(m)
}

func (c *Conn) WriteMsg(m Message) error {
	return c.rw.WriteMsg(m)
}

func (c *Conn) Context() context.Context {
	if getter, ok := c.Conn.(interface{ Context() context.Context }); ok {
		return getter.Context()
	}
	return context.Background()
}

func (c *Conn) WithContext(ctx context.Context) {
	if setter, ok := c.Conn.(interface{ WithContext(context.Context) }); ok {
		setter.WithContext(ctx)
	}
}

type V1ReadWriter struct {
	rw io.ReadWriter
}

func NewV1ReadWriter(rw io.ReadWriter) ReadWriter {
	return &V1ReadWriter{rw: rw}
}

// NewReadWriter wraps rw with the message codec for the selected wire protocol.
// An empty protocol keeps the historical v1 behavior for tests and older call sites.
func NewReadWriter(rw io.ReadWriter, wireProtocol string) (ReadWriter, error) {
	switch wireProtocol {
	case wire.ProtocolV2:
		return NewV2ReadWriter(rw), nil
	case "", wire.ProtocolV1:
		return NewV1ReadWriter(rw), nil
	default:
		return nil, fmt.Errorf("unsupported wire protocol %q", wireProtocol)
	}
}

func (rw *V1ReadWriter) ReadMsg() (Message, error) {
	return ReadMsg(rw.rw)
}

func (rw *V1ReadWriter) ReadMsgInto(m Message) error {
	return ReadMsgInto(rw.rw, m)
}

func (rw *V1ReadWriter) WriteMsg(m Message) error {
	return WriteMsg(rw.rw, m)
}

func AsyncHandler(f func(Message)) func(Message) {
	return func(m Message) {
		go func() {
			defer func() { _ = recover() }()
			f(m)
		}()
	}
}

// Dispatcher is used to send messages to net.Conn or register handlers for messages read from net.Conn.
type Dispatcher struct {
	rw ReadWriter

	sendCh       chan Message
	doneCh       chan struct{}
	stopCh       chan struct{}
	stopOnce     sync.Once
	runOnce      sync.Once
	asyncMu      sync.Mutex
	asyncStopped bool
	asyncWg      sync.WaitGroup
	// Handlers keyed by message type byte (from msgTypeMap) for fast lookup without reflection.
	handlersMu  sync.RWMutex
	msgHandlers map[byte]func(Message)
}

// NewDispatcher uses SetReadDeadline, when supported, and Close, when rw
// implements io.Closer, to interrupt ReadMsg after a write failure. Without a
// working read deadline, Close or the caller must arrange for ReadMsg to return.
// These methods must return in bounded time and must not wait for Done: Done
// closes only after ReadMsg, any synchronous handler, and stop have returned.
func NewDispatcher(rw ReadWriter) *Dispatcher {
	return &Dispatcher{
		rw:          rw,
		sendCh:      make(chan Message, 100),
		doneCh:      make(chan struct{}),
		stopCh:      make(chan struct{}),
		msgHandlers: make(map[byte]func(Message)),
	}
}

// Run starts the dispatcher send and read loops at most once.
func (d *Dispatcher) Run() {
	d.runOnce.Do(func() {
		go d.sendLoop()
		go d.readLoop()
	})
}

// Stop rejects new sends and interrupts ReadMsg when supported by rw. Done remains
// owned by readLoop so the control owner cannot clean up while a handler is running.
func (d *Dispatcher) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		if conn, ok := d.rw.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = conn.SetReadDeadline(time.Now())
		}
		if closer, ok := d.rw.(io.Closer); ok {
			_ = closer.Close()
		}
	})
}

func (d *Dispatcher) stop() {
	d.Stop()
}

func (d *Dispatcher) sendLoop() {
	for {
		select {
		case <-d.stopCh:
			return
		case m := <-d.sendCh:
			if err := d.rw.WriteMsg(m); err != nil {
				d.stop()
				return
			}
		}
	}
}

func (d *Dispatcher) readLoop() {
	defer close(d.doneCh)
	defer d.stop()
	for {
		m, err := d.rw.ReadMsg()
		if err != nil {
			return
		}

		select {
		case <-d.stopCh:
			return
		default:
		}

		d.handlersMu.RLock()
		handler, ok := d.msgHandlers[messageTypeByte(m)]
		d.handlersMu.RUnlock()
		if ok && handler != nil {
			handler(m)
		}
	}
}

// Send queues m for writing. A nil error does not guarantee delivery.
func (d *Dispatcher) Send(m Message) error {
	select {
	case <-d.stopCh:
		return io.EOF
	default:
	}
	return d.enqueue(m)
}

func (d *Dispatcher) enqueue(m Message) error {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case <-d.stopCh:
		return io.EOF
	case d.sendCh <- m:
		// Both cases can be ready if shutdown races with enqueueing. Do not
		// report success when shutdown is already observable after the send.
		select {
		case <-d.stopCh:
			return io.EOF
		default:
			return nil
		}
	case <-timer.C:
		return ErrSendQueueFull
	}
}

func (d *Dispatcher) RegisterHandler(msg Message, handler func(Message)) {
	d.handlersMu.Lock()
	d.msgHandlers[messageTypeByte(msg)] = handler
	d.handlersMu.Unlock()
}

// RegisterAsyncHandler registers an asynchronous handler whose goroutines are
// tracked and can be awaited with WaitAsync.
func (d *Dispatcher) RegisterAsyncHandler(msg Message, handler func(Message)) {
	d.RegisterHandler(msg, func(m Message) {
		d.asyncMu.Lock()
		if d.asyncStopped {
			d.asyncMu.Unlock()
			return
		}
		d.asyncWg.Add(1)
		d.asyncMu.Unlock()

		go func() {
			defer d.asyncWg.Done()
			defer func() { _ = recover() }()
			handler(m)
		}()
	})
}

// WaitAsync prevents new async handler goroutines from being spawned and
// waits for all in-flight goroutines spawned by RegisterAsyncHandler to finish.
func (d *Dispatcher) WaitAsync() {
	d.asyncMu.Lock()
	d.asyncStopped = true
	d.asyncMu.Unlock()
	d.asyncWg.Wait()
}

// messageTypeByte returns the message type byte for a given message.
// Uses a type-switch to avoid reflection in the hot path.
func messageTypeByte(m Message) byte {
	switch m.(type) {
	case *Login:
		return TypeLogin
	case *LoginResp:
		return TypeLoginResp
	case *NewProxy:
		return TypeNewProxy
	case *NewProxyResp:
		return TypeNewProxyResp
	case *CloseProxy:
		return TypeCloseProxy
	case *NewWorkConn:
		return TypeNewWorkConn
	case *ReqWorkConn:
		return TypeReqWorkConn
	case *StartWorkConn:
		return TypeStartWorkConn
	case *NewVisitorConn:
		return TypeNewVisitorConn
	case *NewVisitorConnResp:
		return TypeNewVisitorConnResp
	case *Ping:
		return TypePing
	case *Pong:
		return TypePong
	case *UDPPacket:
		return TypeUDPPacket
	case *NatHoleVisitor:
		return TypeNatHoleVisitor
	case *NatHoleClient:
		return TypeNatHoleClient
	case *NatHoleResp:
		return TypeNatHoleResp
	case *NatHoleSid:
		return TypeNatHoleSid
	case *NatHoleReport:
		return TypeNatHoleReport
	default:
		return 0
	}
}

func (d *Dispatcher) Done() chan struct{} {
	return d.doneCh
}
