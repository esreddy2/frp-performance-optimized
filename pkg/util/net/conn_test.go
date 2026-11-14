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
	"bytes"
	"io"
	stdnet "net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/proto/wire"
)

func TestNewAEADCryptoReadWriterRoundTrip(t *testing.T) {
	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	key := []byte("token")
	transcriptHash := bytes.Repeat([]byte{0x11}, 32)
	clientRW, err := NewAEADCryptoReadWriter(
		clientConn,
		key,
		AEADCryptoRoleClient,
		wire.AEADAlgorithmXChaCha20Poly1305,
		transcriptHash,
	)
	require.NoError(t, err)
	serverRW, err := NewAEADCryptoReadWriter(
		serverConn,
		key,
		AEADCryptoRoleServer,
		wire.AEADAlgorithmXChaCha20Poly1305,
		transcriptHash,
	)
	require.NoError(t, err)

	clientErrCh := make(chan error, 1)
	go func() {
		if _, err := clientRW.Write([]byte("ping")); err != nil {
			clientErrCh <- err
			return
		}
		buf := make([]byte, len("pong"))
		_, err := io.ReadFull(clientRW, buf)
		clientErrCh <- err
	}()

	buf := make([]byte, len("ping"))
	_, err = io.ReadFull(serverRW, buf)
	require.NoError(t, err)
	require.Equal(t, "ping", string(buf))
	_, err = serverRW.Write([]byte("pong"))
	require.NoError(t, err)
	require.NoError(t, <-clientErrCh)
}

func TestNewAEADCryptoReadWriterRejectsDifferentTranscript(t *testing.T) {
	clientConn, serverConn := stdnet.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(time.Second)))
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(time.Second)))

	key := []byte("token")
	clientRW, err := NewAEADCryptoReadWriter(
		clientConn,
		key,
		AEADCryptoRoleClient,
		wire.AEADAlgorithmAES256GCM,
		bytes.Repeat([]byte{0x22}, 32),
	)
	require.NoError(t, err)
	serverRW, err := NewAEADCryptoReadWriter(
		serverConn,
		key,
		AEADCryptoRoleServer,
		wire.AEADAlgorithmAES256GCM,
		bytes.Repeat([]byte{0x33}, 32),
	)
	require.NoError(t, err)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientRW.Write([]byte("ping"))
		writeErrCh <- err
	}()

	buf := make([]byte, len("ping"))
	_, err = io.ReadFull(serverRW, buf)
	require.Error(t, err)
	require.NoError(t, <-writeErrCh)
}

func TestDeriveAEADControlKeysUsesDistinctDirections(t *testing.T) {
	clientToServerKey, serverToClientKey, err := deriveAEADControlKeys(
		[]byte("token"),
		wire.AEADAlgorithmXChaCha20Poly1305,
		bytes.Repeat([]byte{0x44}, 32),
	)
	require.NoError(t, err)
	require.Equal(t, []byte{
		0xa0, 0x58, 0xcd, 0x02, 0x5d, 0x96, 0x98, 0x5f,
		0xeb, 0xeb, 0xff, 0x79, 0xa1, 0x9f, 0x62, 0xb7,
		0x15, 0xe0, 0x53, 0x91, 0x3d, 0xfc, 0x74, 0x77,
		0x05, 0x91, 0x4c, 0x62, 0x4b, 0xf3, 0xd4, 0x95,
	}, clientToServerKey)
	require.NotEqual(t, clientToServerKey, serverToClientKey)
}

func TestNewAEADCryptoReadWriterValidationErrors(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	validHash := bytes.Repeat([]byte{0x01}, 32)

	_, err := NewAEADCryptoReadWriter(c1, []byte("k"), AEADCryptoRoleClient, wire.AEADAlgorithmAES256GCM, nil)
	require.ErrorContains(t, err, "empty transcript hash")

	_, err = NewAEADCryptoReadWriter(c1, []byte("k"), AEADCryptoRoleClient, "unknown-aead", validHash)
	require.Error(t, err)

	_, err = NewAEADCryptoReadWriter(c1, []byte("k"), AEADCryptoRole(99), wire.AEADAlgorithmAES256GCM, validHash)
	require.ErrorContains(t, err, "invalid aead crypto role")
}

func TestNewCryptoReadWriterRoundTrip(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	rw1, err := NewCryptoReadWriter(c1, []byte("shared-secret"))
	require.NoError(t, err)
	rw2, err := NewCryptoReadWriter(c2, []byte("shared-secret"))
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, wErr := rw1.Write([]byte("hello crypto"))
		errCh <- wErr
	}()

	buf := make([]byte, len("hello crypto"))
	_, err = io.ReadFull(rw2, buf)
	require.NoError(t, err)
	require.Equal(t, "hello crypto", string(buf))
	require.NoError(t, <-errCh)
}

func TestContextConnLifecycleAndConcurrency(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Plain net.Conn returns a background context and a valid logger.
	plainCtx := NewContextFromConn(c1)
	require.NotNil(t, plainCtx)
	require.NotNil(t, NewLogFromConn(c1))

	ctx1 := t.Context()
	cc := NewContextConn(ctx1, c1)
	require.Equal(t, ctx1, cc.Context())
	require.Equal(t, ctx1, NewContextFromConn(cc))
	require.NotNil(t, NewLogFromConn(cc))

	// Concurrent WithContext and Context reads must not race.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			cc.WithContext(t.Context())
		}
	}()
	for range 100 {
		_ = cc.Context()
		_ = NewContextFromConn(cc)
		_ = NewLogFromConn(cc)
	}
	<-done
}

func TestWrapReadWriteCloserConnAddresses(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Without underlying conn, LocalAddr and RemoteAddr return nil TCPAddr.
	noUnder := WrapReadWriteCloserToConn(c1, nil)
	require.Nil(t, noUnder.LocalAddr())
	require.Nil(t, noUnder.RemoteAddr())

	customAddr := &stdnet.TCPAddr{IP: stdnet.IPv4(192, 0, 2, 10), Port: 8080}
	noUnder.SetRemoteAddr(customAddr)
	require.Equal(t, customAddr, noUnder.RemoteAddr())

	// With underlying conn, delegates LocalAddr and RemoteAddr until overridden.
	withUnder := WrapReadWriteCloserToConn(c1, c2)
	require.Equal(t, c2.LocalAddr(), withUnder.LocalAddr())
	require.Equal(t, c2.RemoteAddr(), withUnder.RemoteAddr())

	overrideAddr := &stdnet.TCPAddr{IP: stdnet.IPv4(198, 51, 100, 5), Port: 9090}
	withUnder.SetRemoteAddr(overrideAddr)
	require.Equal(t, overrideAddr, withUnder.RemoteAddr())
}

func TestCloseNotifyConnIdempotentAndNonDeadlocking(t *testing.T) {
	t.Run("Close invokes callback once with nil error", func(t *testing.T) {
		c1, c2 := stdnet.Pipe()
		defer c2.Close()

		calledCh := make(chan error, 4)
		var cc *CloseNotifyConn
		cc = WrapCloseNotifyConn(c1, func(err error) {
			// Re-entrant Close inside callback must not deadlock or re-trigger callback.
			_ = cc.Close()
			calledCh <- err
		})

		require.NoError(t, cc.Close())
		require.NoError(t, cc.Close())

		select {
		case err := <-calledCh:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for close notification")
		}
		require.Empty(t, calledCh)
	})

	t.Run("CloseWithError passes error to callback once", func(t *testing.T) {
		c1, c2 := stdnet.Pipe()
		defer c2.Close()

		calledCh := make(chan error, 4)
		cc := WrapCloseNotifyConn(c1, func(err error) {
			calledCh <- err
		})

		expectedErr := io.ErrUnexpectedEOF
		require.NoError(t, cc.CloseWithError(expectedErr))
		require.NoError(t, cc.CloseWithError(io.EOF))
		require.NoError(t, cc.Close())

		select {
		case err := <-calledCh:
			require.ErrorIs(t, err, expectedErr)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for close-with-error notification")
		}
		require.Empty(t, calledCh)
	})
}

func TestStatsConnTracksBytesAndReportsOnce(t *testing.T) {
	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	type statsResult struct {
		read  int64
		write int64
	}
	resCh := make(chan statsResult, 4)
	sc := WrapStatsConn(c1, func(totalRead, totalWrite int64) {
		resCh <- statsResult{read: totalRead, write: totalWrite}
	})

	go func() {
		buf := make([]byte, 6)
		_, _ = io.ReadFull(c2, buf)
		_, _ = c2.Write([]byte("123456789"))
	}()

	n, err := sc.Write([]byte("abcdef"))
	require.NoError(t, err)
	require.Equal(t, 6, n)

	readBuf := make([]byte, 9)
	n, err = io.ReadFull(sc, readBuf)
	require.NoError(t, err)
	require.Equal(t, 9, n)

	require.NoError(t, sc.Close())
	require.NoError(t, sc.Close())

	select {
	case got := <-resCh:
		require.Equal(t, int64(9), got.read)
		require.Equal(t, int64(6), got.write)
	case <-time.After(time.Second):
		t.Fatal("stats callback was not called on Close")
	}
	require.Empty(t, resCh)
}

type embeddedConnWrapper struct {
	stdnet.Conn
}

func TestGetQuicConnFromNetConnUnwrappingAndCycleSafety(t *testing.T) {
	require.Nil(t, GetQuicConnFromNetConn(nil))

	c1, c2 := stdnet.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Unwrapping through all standard wrapper layers returns nil cleanly for non-QUIC conn.
	ctxConn := NewContextConn(t.Context(), c1)
	rwcConn := WrapReadWriteCloserToConn(ctxConn, ctxConn)
	statsConn := WrapStatsConn(rwcConn, nil)
	notifyConn := WrapCloseNotifyConn(statsConn, nil)
	wrapped := &embeddedConnWrapper{Conn: notifyConn}
	require.Nil(t, GetQuicConnFromNetConn(wrapped))

	// A cyclic wrapper chain must terminate and return nil instead of looping infinitely.
	cyclic := &embeddedConnWrapper{}
	cyclic.Conn = cyclic
	require.Nil(t, GetQuicConnFromNetConn(cyclic))

	twoNodeA := &embeddedConnWrapper{}
	twoNodeB := &embeddedConnWrapper{Conn: twoNodeA}
	twoNodeA.Conn = twoNodeB
	require.Nil(t, GetQuicConnFromNetConn(twoNodeA))
}
