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
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type halfPipe struct {
	ch         chan []byte
	closeOnce  sync.Once
	closed     chan struct{}
	leftover   []byte
	mu         sync.Mutex
	rTimer     *time.Timer
	wTimer     *time.Timer
	rTimeoutCh chan struct{}
	wTimeoutCh chan struct{}
}

func newHalfPipe(capacity int) *halfPipe {
	if capacity < 1 {
		capacity = 64
	}
	return &halfPipe{
		ch:     make(chan []byte, capacity),
		closed: make(chan struct{}),
	}
}

func (h *halfPipe) write(p []byte) (int, error) {
	select {
	case <-h.closed:
		return 0, net.ErrClosed
	default:
	}

	h.mu.Lock()
	wTimeoutCh := h.wTimeoutCh
	h.mu.Unlock()

	select {
	case <-wTimeoutCh:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	cp := make([]byte, len(p))
	copy(cp, p)

	select {
	case h.ch <- cp:
		return len(p), nil
	case <-h.closed:
		return 0, net.ErrClosed
	case <-wTimeoutCh:
		return 0, os.ErrDeadlineExceeded
	}
}

func (h *halfPipe) read(p []byte) (int, error) {
	h.mu.Lock()
	if len(h.leftover) > 0 {
		n := copy(p, h.leftover)
		h.leftover = h.leftover[n:]
		h.mu.Unlock()
		return n, nil
	}
	rTimeoutCh := h.rTimeoutCh
	h.mu.Unlock()

	select {
	case <-rTimeoutCh:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	select {
	case chunk, ok := <-h.ch:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		if n < len(chunk) {
			h.mu.Lock()
			h.leftover = chunk[n:]
			h.mu.Unlock()
		}
		return n, nil
	case <-h.closed:
		// Drain any remaining in h.ch before returning EOF
		select {
		case chunk, ok := <-h.ch:
			if ok {
				n := copy(p, chunk)
				if n < len(chunk) {
					h.mu.Lock()
					h.leftover = chunk[n:]
					h.mu.Unlock()
				}
				return n, nil
			}
		default:
		}
		return 0, io.EOF
	case <-rTimeoutCh:
		return 0, os.ErrDeadlineExceeded
	}
}

func (h *halfPipe) close() {
	h.closeOnce.Do(func() {
		close(h.closed)
	})
}

func (h *halfPipe) setReadDeadline(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rTimer != nil {
		h.rTimer.Stop()
		h.rTimer = nil
	}
	if t.IsZero() {
		h.rTimeoutCh = nil
		return
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan struct{})
		close(ch)
		h.rTimeoutCh = ch
		return
	}
	ch := make(chan struct{})
	h.rTimeoutCh = ch
	h.rTimer = time.AfterFunc(d, func() {
		close(ch)
	})
}

func (h *halfPipe) setWriteDeadline(t time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.wTimer != nil {
		h.wTimer.Stop()
		h.wTimer = nil
	}
	if t.IsZero() {
		h.wTimeoutCh = nil
		return
	}
	d := time.Until(t)
	if d <= 0 {
		ch := make(chan struct{})
		close(ch)
		h.wTimeoutCh = ch
		return
	}
	ch := make(chan struct{})
	h.wTimeoutCh = ch
	h.wTimer = time.AfterFunc(d, func() {
		close(ch)
	})
}

type PipeSide struct {
	in     *halfPipe
	out    *halfPipe
	closed atomic.Bool
}

func (s *PipeSide) Read(p []byte) (int, error) {
	return s.in.read(p)
}

func (s *PipeSide) Write(p []byte) (int, error) {
	return s.out.write(p)
}

func (s *PipeSide) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.in.close()
		s.out.close()
	}
	return nil
}

func (s *PipeSide) LocalAddr() net.Addr {
	return pipeAddr("pipe")
}

func (s *PipeSide) RemoteAddr() net.Addr {
	return pipeAddr("pipe")
}

func (s *PipeSide) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *PipeSide) SetReadDeadline(t time.Time) error {
	s.in.setReadDeadline(t)
	return nil
}

func (s *PipeSide) SetWriteDeadline(t time.Time) error {
	s.out.setWriteDeadline(t)
	return nil
}

// NewBufferedPipe creates an asynchronous, buffered, full-duplex in-memory pipe.
// Writes to one end buffer up to capacity chunks before blocking, eliminating
// synchronous throughput bottlenecks inherent in unbuffered net.Pipe().
func NewBufferedPipe(capacity int) (net.Conn, net.Conn) {
	h1 := newHalfPipe(capacity)
	h2 := newHalfPipe(capacity)

	side1 := &PipeSide{
		in:  h2,
		out: h1,
	}
	side2 := &PipeSide{
		in:  h1,
		out: h2,
	}
	return side1, side2
}
