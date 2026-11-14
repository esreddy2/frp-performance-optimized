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

package tcpmux

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/util/vhost"
)

func TestHTTPConnectTCPMuxerAuth(t *testing.T) {
	muxer := &HTTPConnectTCPMuxer{}

	t.Run("matching credentials", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		ok, err := muxer.auth(c1, "alice", "s3cr3t", map[string]string{
			"HTTPUser": "alice",
			"HTTPPwd":  "s3cr3t",
		})
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("mismatching credentials returns 407", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			user string
			pass string
		}{
			{name: "wrong user", user: "bob", pass: "s3cr3t"},
			{name: "wrong pass", user: "alice", pass: "wrong"},
			{name: "empty creds", user: "", pass: ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c1, c2 := net.Pipe()
				defer c1.Close()
				defer c2.Close()

				errCh := make(chan error, 1)
				respCh := make(chan *http.Response, 1)
				go func() {
					resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
					if err != nil {
						errCh <- err
						return
					}
					respCh <- resp
				}()

				ok, err := muxer.auth(c1, "alice", "s3cr3t", map[string]string{
					"HTTPUser": tc.user,
					"HTTPPwd":  tc.pass,
				})
				require.NoError(t, err)
				require.False(t, ok)

				select {
				case err := <-errCh:
					t.Fatal(err)
				case resp := <-respCh:
					defer resp.Body.Close()
					require.Equal(t, http.StatusProxyAuthRequired, resp.StatusCode)
				}
			})
		}
	})
}

func TestHTTPConnectTCPMuxerNonPassthroughRoutingAndAuth(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer baseLn.Close()

	muxer, err := NewHTTPConnectTCPMuxer(baseLn, false, 2*time.Second)
	require.NoError(t, err)

	// Route 1: public route for app.example.com
	appLn, err := muxer.Listen(t.Context(), &vhost.RouteConfig{
		Domain: "app.example.com",
	})
	require.NoError(t, err)
	defer appLn.Close()

	// Route 2 & 3: user-routed endpoints on shared.example.com with credentials
	aliceLn, err := muxer.Listen(t.Context(), &vhost.RouteConfig{
		Domain:          "shared.example.com",
		RouteByHTTPUser: "alice",
		Username:        "alice",
		Password:        "alice-pw",
	})
	require.NoError(t, err)
	defer aliceLn.Close()

	bobLn, err := muxer.Listen(t.Context(), &vhost.RouteConfig{
		Domain:          "shared.example.com",
		RouteByHTTPUser: "bob",
		Username:        "bob",
		Password:        "bob-pw",
	})
	require.NoError(t, err)
	defer bobLn.Close()

	t.Run("connect to public route receives 200 OK and tunnels stream", func(t *testing.T) {
		client, err := net.Dial("tcp", baseLn.Addr().String())
		require.NoError(t, err)
		defer client.Close()

		_, err = client.Write([]byte("CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n\r\n"))
		require.NoError(t, err)

		backendConn, err := appLn.Accept()
		require.NoError(t, err)
		defer backendConn.Close()

		br := bufio.NewReader(client)
		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		_, err = client.Write([]byte("hello-backend"))
		require.NoError(t, err)
		buf := make([]byte, len("hello-backend"))
		_, err = io.ReadFull(backendConn, buf)
		require.NoError(t, err)
		require.Equal(t, "hello-backend", string(buf))
	})

	t.Run("RouteByHTTPUser routes to matching user listener and enforces auth", func(t *testing.T) {
		client, err := net.Dial("tcp", baseLn.Addr().String())
		require.NoError(t, err)
		defer client.Close()

		bobAuth := base64.StdEncoding.EncodeToString([]byte("bob:bob-pw"))
		req := "CONNECT shared.example.com:443 HTTP/1.1\r\n" +
			"Host: shared.example.com:443\r\n" +
			"Proxy-Authorization: Basic " + bobAuth + "\r\n\r\n"
		_, err = client.Write([]byte(req))
		require.NoError(t, err)

		backendConn, err := bobLn.Accept()
		require.NoError(t, err)
		defer backendConn.Close()

		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Wrong password for alice returns 407 Proxy Authentication Required.
		badClient, err := net.Dial("tcp", baseLn.Addr().String())
		require.NoError(t, err)
		defer badClient.Close()

		badAuth := base64.StdEncoding.EncodeToString([]byte("alice:wrong-pw"))
		badReq := "CONNECT shared.example.com:443 HTTP/1.1\r\n" +
			"Host: shared.example.com:443\r\n" +
			"Proxy-Authorization: Basic " + badAuth + "\r\n\r\n"
		_, err = badClient.Write([]byte(badReq))
		require.NoError(t, err)

		badResp, err := http.ReadResponse(bufio.NewReader(badClient), nil)
		require.NoError(t, err)
		defer badResp.Body.Close()
		require.Equal(t, http.StatusProxyAuthRequired, badResp.StatusCode)
	})

	t.Run("unregistered domain returns 404 Not Found", func(t *testing.T) {
		client, err := net.Dial("tcp", baseLn.Addr().String())
		require.NoError(t, err)
		defer client.Close()

		_, err = client.Write([]byte("CONNECT unknown.example.com:443 HTTP/1.1\r\nHost: unknown.example.com:443\r\n\r\n"))
		require.NoError(t, err)

		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("non-CONNECT method is rejected", func(t *testing.T) {
		_, _, _, err := muxer.readHTTPConnectRequest(strings.NewReader("GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"))
		require.ErrorContains(t, err, "must be of method CONNECT")
	})
}

func TestHTTPConnectTCPMuxerPassthroughForwardsConnectRequest(t *testing.T) {
	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer baseLn.Close()

	muxer, err := NewHTTPConnectTCPMuxer(baseLn, true, 2*time.Second)
	require.NoError(t, err)

	ptLn, err := muxer.Listen(t.Context(), &vhost.RouteConfig{
		Domain: "pt.example.com",
	})
	require.NoError(t, err)
	defer ptLn.Close()

	client, err := net.Dial("tcp", baseLn.Addr().String())
	require.NoError(t, err)
	defer client.Close()

	rawConnect := "CONNECT pt.example.com:8443 HTTP/1.1\r\nHost: pt.example.com:8443\r\n\r\n"
	_, err = client.Write([]byte(rawConnect + "stream-data"))
	require.NoError(t, err)

	backendConn, err := ptLn.Accept()
	require.NoError(t, err)
	defer backendConn.Close()

	// In passthrough mode, the backend receives the original CONNECT HTTP request
	// followed by the stream data.
	br := bufio.NewReader(backendConn)
	req, err := http.ReadRequest(br)
	require.NoError(t, err)
	require.Equal(t, "CONNECT", req.Method)
	require.Equal(t, "pt.example.com:8443", req.Host)

	trailing := make([]byte, len("stream-data"))
	_, err = io.ReadFull(br, trailing)
	require.NoError(t, err)
	require.Equal(t, "stream-data", string(trailing))
}
