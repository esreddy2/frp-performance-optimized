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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInternalListenerDeliverAndClose(t *testing.T) {
	l := NewInternalListener()
	require.Equal(t, "internal", l.Addr().Network())
	require.Equal(t, "internal", l.Addr().String())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	require.NoError(t, l.PutConn(c1))

	accepted, err := l.Accept()
	require.NoError(t, err)
	require.Same(t, c1, accepted)

	// Closing the listener is idempotent and unblocks waiting Accept calls.
	acceptErrCh := make(chan error, 1)
	go func() {
		_, aErr := l.Accept()
		acceptErrCh <- aErr
	}()

	require.NoError(t, l.Close())
	require.NoError(t, l.Close())

	select {
	case aErr := <-acceptErrCh:
		require.ErrorContains(t, aErr, "listener closed")
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock when InternalListener closed")
	}

	// PutConn after Close must return an error and close the submitted connection.
	c3, c4 := net.Pipe()
	defer c4.Close()
	err = l.PutConn(c3)
	require.ErrorContains(t, err, "listener is closed")
	_, readErr := c4.Read(make([]byte, 1))
	require.ErrorIs(t, readErr, io.EOF)
}

func TestInternalListenerOverflowClosesExcessConn(t *testing.T) {
	l := NewInternalListener()
	defer l.Close()

	// Fill the 128-slot buffer.
	peers := make([]net.Conn, 128)
	for i := range 128 {
		c1, c2 := net.Pipe()
		peers[i] = c2
		t.Cleanup(func() {
			c1.Close()
			c2.Close()
		})
		require.NoError(t, l.PutConn(c1))
	}

	// The 129th connection without a reader should not block and should be closed.
	extraClient, extraPeer := net.Pipe()
	defer extraPeer.Close()
	require.ErrorIs(t, l.PutConn(extraClient), ErrInternalListenerQueueFull)

	_, err := extraPeer.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}
