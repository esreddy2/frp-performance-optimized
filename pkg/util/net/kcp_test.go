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
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	kcp "github.com/xtaci/kcp-go/v5"
)

func TestKCPListenerAcceptErrorBackoff(t *testing.T) {
	l := &KCPListener{
		acceptCh: make(chan net.Conn, 1),
		done:     make(chan struct{}),
	}

	var calls atomic.Int32
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		l.runAcceptLoop(func() (*kcp.UDPSession, error) {
			calls.Add(1)
			return nil, errors.New("temporary accept error")
		})
	}()

	// With exponential backoff starting at 5ms (5ms -> 10ms -> 20ms -> 40ms -> 80ms),
	// in 50ms there should be only a handful of calls, not a busy-spin.
	time.Sleep(50 * time.Millisecond)
	count := calls.Load()
	require.GreaterOrEqual(t, count, int32(2))
	require.Less(t, count, int32(10), "accept loop should back off instead of busy-spinning")

	close(l.done)
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("runAcceptLoop did not exit promptly when done was closed")
	}
}
