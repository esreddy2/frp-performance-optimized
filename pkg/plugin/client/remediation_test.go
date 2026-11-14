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

//go:build !frps

package client

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	gosocks5 "github.com/armon/go-socks5"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/vnet"
)

// CANON-053: Listener.PutConn does not deadlock with Close() when channel is full
func TestListenerPutConnDeadlockOnClose(t *testing.T) {
	require := require.New(t)

	ln := NewProxyListener()

	// Fill the buffered channel (capacity 64)
	for range 64 {
		p1, p2 := net.Pipe()
		defer p1.Close()
		defer p2.Close()
		require.NoError(ln.PutConn(p1))
	}

	pBlocked1, pBlocked2 := net.Pipe()
	defer pBlocked1.Close()
	defer pBlocked2.Close()

	putErrCh := make(chan error, 1)
	go func() {
		putErrCh <- ln.PutConn(pBlocked1)
	}()

	// Ensure PutConn has attempted to send and is blocked on channel
	time.Sleep(50 * time.Millisecond)

	closeDone := make(chan struct{})
	go func() {
		_ = ln.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
		// Close succeeded without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("deadlock: Close() blocked on Listener.mu while PutConn held mutex")
	}

	select {
	case err := <-putErrCh:
		require.Error(err)
		require.Contains(err.Error(), "listener closed")
	case <-time.After(2 * time.Second):
		t.Fatal("PutConn did not unblock after Close()")
	}
}

// CANON-057: VirtualNetPlugin.Handle does not resurrect connections after Close()
func TestVirtualNetPluginPostCloseNoLeak(t *testing.T) {
	require := require.New(t)

	controller := vnet.NewController(v1.VirtualNetConfig{})
	defer controller.Stop()

	p, err := NewVirtualNetPlugin(PluginContext{
		VnetController: controller,
	}, &v1.VirtualNetPluginOptions{})
	require.NoError(err)

	vnetPlugin := p.(*VirtualNetPlugin)
	require.NoError(vnetPlugin.Close())

	c1, c2 := net.Pipe()
	defer c1.Close()

	vnetPlugin.Handle(context.Background(), &ConnectionInfo{
		Conn:           c2,
		UnderlyingConn: c2,
	})

	// Connection c2 should be closed immediately because plugin is closed
	buf := make([]byte, 1)
	_ = c1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = c1.Read(buf)
	require.ErrorIs(err, io.EOF)

	// conns map must remain nil and not be resurrected
	require.Nil(vnetPlugin.conns)
}

// CANON-050 & CANON-061: StaticFilePlugin directory traversal, empty LocalPath, HEAD support, prefix
func TestStaticFilePluginSecurityAndStandards(t *testing.T) {
	require := require.New(t)

	// 1. Empty LocalPath must be rejected (CANON-050)
	_, err := NewStaticFilePlugin(PluginContext{}, &v1.StaticFilePluginOptions{
		LocalPath: "",
	})
	require.Error(err)

	// Create root directory and outside directory
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "root")
	outsideDir := filepath.Join(tempDir, "outside")
	require.NoError(os.MkdirAll(rootDir, 0o700))
	require.NoError(os.MkdirAll(outsideDir, 0o700))

	require.NoError(os.WriteFile(filepath.Join(rootDir, "hello.txt"), []byte("hello world"), 0o600))
	require.NoError(os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("secret data"), 0o600))

	// Create symlink pointing outside root
	require.NoError(os.Symlink(filepath.Join(outsideDir, "secret.txt"), filepath.Join(rootDir, "escape.txt")))

	sp, err := NewStaticFilePlugin(PluginContext{}, &v1.StaticFilePluginOptions{
		LocalPath:   rootDir,
		StripPrefix: "/static/",
	})
	require.NoError(err)
	defer sp.Close()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go sp.Handle(context.Background(), &ConnectionInfo{Conn: c2, UnderlyingConn: c2})

	// 2. Request through symlink escaping root must be rejected (CANON-050)
	_ = c1.SetDeadline(time.Now().Add(2 * time.Second))
	reqStr := "GET /static/escape.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
	_, err = io.WriteString(c1, reqStr)
	require.NoError(err)

	resp, err := http.ReadResponse(bufio.NewReader(c1), nil)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Contains([]int{http.StatusForbidden, http.StatusNotFound}, resp.StatusCode)

	// 3. Test HTTP HEAD request is supported (CANON-061)
	hc1, hc2 := net.Pipe()
	defer hc1.Close()
	defer hc2.Close()
	go sp.Handle(context.Background(), &ConnectionInfo{Conn: hc2, UnderlyingConn: hc2})

	_ = hc1.SetDeadline(time.Now().Add(2 * time.Second))
	headReq := "HEAD /static/hello.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
	_, err = io.WriteString(hc1, headReq)
	require.NoError(err)

	headResp, err := http.ReadResponse(bufio.NewReader(hc1), nil)
	require.NoError(err)
	_ = headResp.Body.Close()
	require.Equal(http.StatusOK, headResp.StatusCode)
}

// CANON-049 & CANON-061: HTTPProxy destination filter and 502 Bad Gateway
func TestHTTPProxySSRFAndStatus(t *testing.T) {
	require := require.New(t)

	hp := &HTTPProxy{
		opts: &v1.HTTPProxyPluginOptions{},
		l:    NewProxyListener(),
	}

	// 1. CONNECT to metadata IP 169.254.169.254 must return 403 Forbidden (CANON-049)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go hp.Handle(context.Background(), &ConnectionInfo{Conn: c2, UnderlyingConn: c2})

	_ = c1.SetDeadline(time.Now().Add(2 * time.Second))
	connectMetadata := "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n"
	_, err := io.WriteString(c1, connectMetadata)
	require.NoError(err)

	resp, err := http.ReadResponse(bufio.NewReader(c1), nil)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusForbidden, resp.StatusCode)

	// 2. CONNECT to unreachable host must return 502 Bad Gateway (CANON-061)
	c3, c4 := net.Pipe()
	defer c3.Close()
	defer c4.Close()
	go hp.Handle(context.Background(), &ConnectionInfo{Conn: c4, UnderlyingConn: c4})

	_ = c3.SetDeadline(time.Now().Add(2 * time.Second))
	// Connect to closed port on localhost for immediate dial failure (connection refused)
	connectUnreachable := "CONNECT 127.0.0.1:54321 HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n"
	_, err = io.WriteString(c3, connectUnreachable)
	require.NoError(err)

	resp2, err := http.ReadResponse(bufio.NewReader(c3), nil)
	require.NoError(err)
	_ = resp2.Body.Close()
	require.Equal(http.StatusBadGateway, resp2.StatusCode)
}

// CANON-051: SOCKS5 safeRuleSet blocks restricted destinations
func TestSocks5RuleSetBlocksRestricted(t *testing.T) {
	require := require.New(t)

	ruleSet := &safeSocks5RuleSet{}

	// Link-local metadata
	_, allowed := ruleSet.Allow(context.Background(), &gosocks5.Request{
		DestAddr: &gosocks5.AddrSpec{
			IP:   net.ParseIP("169.254.169.254"),
			Port: 80,
		},
	})
	require.False(allowed)

	// Google metadata host
	_, allowed = ruleSet.Allow(context.Background(), &gosocks5.Request{
		DestAddr: &gosocks5.AddrSpec{
			FQDN: "metadata.google.internal",
			Port: 80,
		},
	})
	require.False(allowed)

	// Normal public IP allowed
	_, allowed = ruleSet.Allow(context.Background(), &gosocks5.Request{
		DestAddr: &gosocks5.AddrSpec{
			IP:   net.ParseIP("8.8.8.8"),
			Port: 53,
		},
	})
	require.True(allowed)
}
