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
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/transport"
)

func TestSetDefaultDNSAddress(t *testing.T) {
	origResolver := net.DefaultResolver
	t.Cleanup(func() {
		net.DefaultResolver = origResolver
	})

	SetDefaultDNSAddress("127.0.0.1")
	require.NotNil(t, net.DefaultResolver)
	require.True(t, net.DefaultResolver.PreferGo)

	SetDefaultDNSAddress("127.0.0.1:5353")
	require.NotNil(t, net.DefaultResolver)
}

func TestDialHookCustomTLSHeadByte(t *testing.T) {
	t.Run("writes FRP TLS head byte when enabled", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		hook := DialHookCustomTLSHeadByte(true, false)
		errCh := make(chan error, 1)
		go func() {
			_, _, err := hook(t.Context(), c1, "127.0.0.1:7000")
			errCh <- err
		}()

		buf := make([]byte, 1)
		_, err := io.ReadFull(c2, buf)
		require.NoError(t, err)
		require.Equal(t, byte(FRPTLSHeadByte), buf[0])
		require.NoError(t, <-errCh)
	})

	t.Run("skips head byte when disabled or TLS off", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		hookTLSOff := DialHookCustomTLSHeadByte(false, false)
		_, out, err := hookTLSOff(t.Context(), c1, "127.0.0.1:7000")
		require.NoError(t, err)
		require.Same(t, c1, out)

		hookCustomOff := DialHookCustomTLSHeadByte(true, true)
		_, out, err = hookCustomOff(t.Context(), c1, "127.0.0.1:7000")
		require.NoError(t, err)
		require.Same(t, c1, out)
	})

	t.Run("propagates write error on closed conn", func(t *testing.T) {
		c1, c2 := net.Pipe()
		_ = c1.Close()
		_ = c2.Close()

		hook := DialHookCustomTLSHeadByte(true, false)
		_, _, err := hook(t.Context(), c1, "127.0.0.1:7000")
		require.Error(t, err)
	})
}

func TestDialHookWebsocketWithWebsocketListener(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	wl := NewWebsocketListener(tcpLn)
	defer wl.Close()

	rawClient, err := net.Dial("tcp", wl.Addr().String())
	require.NoError(t, err)
	defer rawClient.Close()

	hook := DialHookWebsocket("ws", "")
	_, wsClient, err := hook(t.Context(), rawClient, wl.Addr().String())
	require.NoError(t, err)
	defer wsClient.Close()

	wsServer, err := wl.Accept()
	require.NoError(t, err)
	defer wsServer.Close()

	// Binary payload (including invalid UTF-8 bytes) must round-trip intact.
	binaryPayload := []byte{0x00, 0xff, 0xfe, 0x80, 0x42}
	_, err = wsClient.Write(binaryPayload)
	require.NoError(t, err)

	got := make([]byte, len(binaryPayload))
	_, err = io.ReadFull(wsServer, got)
	require.NoError(t, err)
	require.Equal(t, binaryPayload, got)
}

func TestCheckAndEnableTLSServerConnWithTimeout(t *testing.T) {
	serverTLS, err := transport.NewServerTLSConfig("", "", "")
	require.NoError(t, err)
	clientTLS, err := transport.NewClientTLSConfig("", "", "", "example.com")
	require.NoError(t, err)

	t.Run("custom FRP TLS head byte completes handshake and transfers data", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		errCh := make(chan error, 1)
		go func() {
			hook := DialHookCustomTLSHeadByte(true, false)
			_, _, hErr := hook(t.Context(), cClient, "example.com")
			if hErr != nil {
				errCh <- hErr
				return
			}
			tlsClient := tls.Client(cClient, clientTLS)
			if hErr := tlsClient.Handshake(); hErr != nil {
				errCh <- hErr
				return
			}
			_, wErr := tlsClient.Write([]byte("custom-tls-msg"))
			errCh <- wErr
		}()

		out, isTLS, custom, err := CheckAndEnableTLSServerConnWithTimeout(cServer, serverTLS, true, 2*time.Second)
		require.NoError(t, err)
		require.True(t, isTLS)
		require.True(t, custom)
		defer out.Close()

		buf := make([]byte, len("custom-tls-msg"))
		_, err = io.ReadFull(out, buf)
		require.NoError(t, err)
		require.Equal(t, "custom-tls-msg", string(buf))
		require.NoError(t, <-errCh)
	})

	t.Run("standard TLS handshake (0x16) succeeds with custom=false", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		errCh := make(chan error, 1)
		go func() {
			tlsClient := tls.Client(cClient, clientTLS)
			_, wErr := tlsClient.Write([]byte("std-tls-msg"))
			errCh <- wErr
		}()

		out, isTLS, custom, err := CheckAndEnableTLSServerConnWithTimeout(cServer, serverTLS, true, 2*time.Second)
		require.NoError(t, err)
		require.True(t, isTLS)
		require.False(t, custom)
		defer out.Close()

		buf := make([]byte, len("std-tls-msg"))
		_, err = io.ReadFull(out, buf)
		require.NoError(t, err)
		require.Equal(t, "std-tls-msg", string(buf))
		require.NoError(t, <-errCh)
	})

	t.Run("plaintext connection preserves first byte when tlsOnly is false", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		go func() {
			_, _ = cClient.Write([]byte("PLAIN"))
		}()

		out, isTLS, custom, err := CheckAndEnableTLSServerConnWithTimeout(cServer, serverTLS, false, time.Second)
		require.NoError(t, err)
		require.False(t, isTLS)
		require.False(t, custom)

		buf := make([]byte, 5)
		_, err = io.ReadFull(out, buf)
		require.NoError(t, err)
		require.Equal(t, "PLAIN", string(buf))
	})

	t.Run("plaintext connection rejected when tlsOnly is true", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		go func() {
			_, _ = cClient.Write([]byte("PLAIN"))
		}()

		out, isTLS, custom, err := CheckAndEnableTLSServerConnWithTimeout(cServer, serverTLS, true, time.Second)
		require.ErrorContains(t, err, "non-TLS connection received on a TlsOnly server")
		require.Nil(t, out)
		require.False(t, isTLS)
		require.False(t, custom)
	})

	t.Run("custom TLS head byte followed by stalled handshake fails within timeout", func(t *testing.T) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		go func() {
			_, _ = cClient.Write([]byte{byte(FRPTLSHeadByte)})
			// Do not send TLS ClientHello; let server handshake deadline expire.
		}()

		out, isTLS, custom, err := CheckAndEnableTLSServerConnWithTimeout(cServer, serverTLS, false, 50*time.Millisecond)
		require.Error(t, err)
		require.Nil(t, out)
		require.False(t, isTLS)
		require.False(t, custom)
	})
}
