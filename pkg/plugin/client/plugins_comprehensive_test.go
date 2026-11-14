package client

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pp "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type closeTrackingRWC struct {
	io.ReadWriteCloser
	closed atomic.Bool
}

func (c *closeTrackingRWC) Close() error {
	c.closed.Store(true)
	return c.ReadWriteCloser.Close()
}

func TestPluginRegistryAndProxyListenerConcurrency(t *testing.T) {
	require := require.New(t)

	_, err := Create("nonexistent_plugin", PluginContext{}, nil)
	require.ErrorContains(err, "is not registered")

	require.Panics(func() {
		Register(v1.PluginHTTP2HTTP, NewHTTP2HTTPPlugin)
	})

	ln := NewProxyListener()
	require.Nil(ln.Addr())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	require.NoError(ln.PutConn(c1))
	accepted, err := ln.Accept()
	require.NoError(err)
	require.Equal(c1, accepted)

	// Concurrent PutConn and Close must not race and rejected connections must be closed
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			p1, p2 := net.Pipe()
			defer p2.Close()
			_ = ln.PutConn(p1)
			_ = p1.Close()
		})
	}
	wg.Go(func() {
		_ = ln.Close()
	})
	wg.Wait()

	// PutConn after Close returns error and closes the passed connection
	p1, p2 := net.Pipe()
	defer p2.Close()
	tracked := &closeTrackingRWC{ReadWriteCloser: p1}
	err = ln.PutConn(&netConnAdapter{Conn: p1, rwc: tracked})
	require.ErrorContains(err, "listener closed")
	require.True(tracked.closed.Load())
}

type netConnAdapter struct {
	net.Conn
	rwc io.ReadWriteCloser
}

func (a *netConnAdapter) Close() error {
	return a.rwc.Close()
}

func TestHTTP2HTTPAndHTTP2HTTPSPlugins(t *testing.T) {
	require := require.New(t)

	// Local HTTP backend
	var gotHost, gotHeader string
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotHeader = r.Header.Get("X-Plugin-Header")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("from-http-backend"))
	}))
	defer httpBackend.Close()
	backendHost := strings.TrimPrefix(httpBackend.URL, "http://")

	p, err := Create(v1.PluginHTTP2HTTP, PluginContext{Name: "p-h2h"}, &v1.HTTP2HTTPPluginOptions{
		LocalAddr:         backendHost,
		HostHeaderRewrite: "rewritten.local",
		RequestHeaders: v1.HeaderOperations{
			Set: map[string]string{"X-Plugin-Header": "injected"},
		},
	})
	require.NoError(err)
	defer p.Close()
	require.Equal(v1.PluginHTTP2HTTP, p.Name())
	require.NoError(p.(*HTTP2HTTPPlugin).Reload())
	require.NoError(p.(*HTTP2HTTPPlugin).ReloadError())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go p.Handle(context.Background(), &ConnectionInfo{Conn: c2, UnderlyingConn: c2})

	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(c1, "GET /test HTTP/1.1\r\nHost: orig.local\r\nConnection: close\r\n\r\n")
	require.NoError(err)

	resp, err := http.ReadResponse(bufio.NewReader(c1), nil)
	require.NoError(err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
	require.Equal("from-http-backend", string(body))
	require.Equal("rewritten.local", gotHost)
	require.Equal("injected", gotHeader)

	// Local HTTPS backend for http2https
	httpsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("from-https-backend:" + r.Host))
	}))
	defer httpsBackend.Close()
	httpsBackendHost := strings.TrimPrefix(httpsBackend.URL, "https://")

	p2s, err := Create(v1.PluginHTTP2HTTPS, PluginContext{Name: "p-h2s"}, &v1.HTTP2HTTPSPluginOptions{
		LocalAddr:         httpsBackendHost,
		HostHeaderRewrite: "secure.local",
	})
	require.NoError(err)
	defer p2s.Close()
	require.Equal(v1.PluginHTTP2HTTPS, p2s.Name())

	s1, s2 := net.Pipe()
	defer s1.Close()
	defer s2.Close()
	go p2s.Handle(context.Background(), &ConnectionInfo{Conn: s2, UnderlyingConn: s2})

	_ = s1.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(s1, "GET / HTTP/1.1\r\nHost: orig.local\r\nConnection: close\r\n\r\n")
	require.NoError(err)

	resp2, err := http.ReadResponse(bufio.NewReader(s1), nil)
	require.NoError(err)
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(err)
	_ = resp2.Body.Close()
	require.Equal(http.StatusOK, resp2.StatusCode)
	require.Equal("from-https-backend:secure.local", string(body2))
}

func TestHTTPS2HTTPAndHTTPS2HTTPSPlugins(t *testing.T) {
	require := require.New(t)

	var gotXFF string
	httpBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https2http-ok"))
	}))
	defer httpBackend.Close()
	backendHost := strings.TrimPrefix(httpBackend.URL, "http://")

	// Empty CrtPath/KeyPath uses auto-generated self-signed TLS certificate
	p, err := Create(v1.PluginHTTPS2HTTP, PluginContext{Name: "p-s2h"}, &v1.HTTPS2HTTPPluginOptions{
		LocalAddr:         backendHost,
		HostHeaderRewrite: "internal.local",
	})
	require.NoError(err)
	defer p.Close()
	require.Equal(v1.PluginHTTPS2HTTP, p.Name())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	srcAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 54321}
	go p.Handle(context.Background(), &ConnectionInfo{
		Conn:           c2,
		UnderlyingConn: c2,
		SrcAddr:        srcAddr,
	})

	tlsClient := tls.Client(c1, &tls.Config{InsecureSkipVerify: true})
	_ = tlsClient.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(tlsClient, "GET / HTTP/1.1\r\nHost: ext.local\r\nConnection: close\r\n\r\n")
	require.NoError(err)

	resp, err := http.ReadResponse(bufio.NewReader(tlsClient), nil)
	require.NoError(err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
	require.Equal("https2http-ok", string(body))
	require.Contains(gotXFF, "203.0.113.9")

	// HTTPS2HTTPS plugin
	httpsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https2https-ok"))
	}))
	defer httpsBackend.Close()
	httpsBackendHost := strings.TrimPrefix(httpsBackend.URL, "https://")

	ps2s, err := Create(v1.PluginHTTPS2HTTPS, PluginContext{Name: "p-s2s"}, &v1.HTTPS2HTTPSPluginOptions{
		LocalAddr: httpsBackendHost,
	})
	require.NoError(err)
	defer ps2s.Close()
	require.Equal(v1.PluginHTTPS2HTTPS, ps2s.Name())

	s1, s2 := net.Pipe()
	defer s1.Close()
	defer s2.Close()
	go ps2s.Handle(context.Background(), &ConnectionInfo{Conn: s2, UnderlyingConn: s2, SrcAddr: srcAddr})

	tlsClient2 := tls.Client(s1, &tls.Config{InsecureSkipVerify: true})
	_ = tlsClient2.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = io.WriteString(tlsClient2, "GET / HTTP/1.1\r\nHost: ext.local\r\nConnection: close\r\n\r\n")
	require.NoError(err)

	resp2, err := http.ReadResponse(bufio.NewReader(tlsClient2), nil)
	require.NoError(err)
	body2, err := io.ReadAll(resp2.Body)
	require.NoError(err)
	_ = resp2.Body.Close()
	require.Equal(http.StatusOK, resp2.StatusCode)
	require.Equal("https2https-ok", string(body2))
}

func TestStaticFilePlugin(t *testing.T) {
	require := require.New(t)

	dir := t.TempDir()
	require.NoError(os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("static-content-123"), 0o600))

	p, err := Create(v1.PluginStaticFile, PluginContext{Name: "p-static"}, &v1.StaticFilePluginOptions{
		LocalPath:    dir,
		StripPrefix:  "static",
		HTTPUser:     "alice",
		HTTPPassword: "secret",
	})
	require.NoError(err)
	defer p.Close()
	require.Equal(v1.PluginStaticFile, p.Name())

	// 1. Authenticated request succeeds
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go p.Handle(context.Background(), &ConnectionInfo{Conn: c2, UnderlyingConn: c2})

	req, err := http.NewRequest("GET", "http://example.com/static/hello.txt", nil)
	require.NoError(err)
	req.SetBasicAuth("alice", "secret")
	req.Close = true
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	require.NoError(req.Write(c1))

	resp, err := http.ReadResponse(bufio.NewReader(c1), req)
	require.NoError(err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
	require.Equal("static-content-123", string(body))

	// 2. Unauthenticated request returns 401 Unauthorized
	u1, u2 := net.Pipe()
	defer u1.Close()
	defer u2.Close()
	go p.Handle(context.Background(), &ConnectionInfo{Conn: u2, UnderlyingConn: u2})

	unauthReq, err := http.NewRequest("GET", "http://example.com/static/hello.txt", nil)
	require.NoError(err)
	unauthReq.Close = true
	_ = u1.SetDeadline(time.Now().Add(3 * time.Second))
	require.NoError(unauthReq.Write(u1))

	unauthResp, err := http.ReadResponse(bufio.NewReader(u1), unauthReq)
	require.NoError(err)
	_ = unauthResp.Body.Close()
	require.Equal(http.StatusUnauthorized, unauthResp.StatusCode)
}

func TestSocks5AndTLS2RawAndVirtualNetPlugins(t *testing.T) {
	require := require.New(t)

	// 1. Local TCP echo server for Socks5 and TLS2Raw
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer echoLn.Close()
	go func() {
		for {
			c, acceptErr := echoLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoAddr := echoLn.Addr().(*net.TCPAddr)

	// 2. Socks5Plugin with credentials
	socksPlugin, err := Create(v1.PluginSocks5, PluginContext{Name: "p-socks5"}, &v1.Socks5PluginOptions{
		Username: "u1",
		Password: "p1",
	})
	require.NoError(err)
	defer socksPlugin.Close()
	require.Equal(v1.PluginSocks5, socksPlugin.Name())

	sc1, sc2 := net.Pipe()
	defer sc1.Close()
	defer sc2.Close()
	go socksPlugin.Handle(context.Background(), &ConnectionInfo{Conn: sc2, UnderlyingConn: sc2})

	_ = sc1.SetDeadline(time.Now().Add(3 * time.Second))
	// SOCKS5 greeting offering username/password auth (0x02)
	_, err = sc1.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(err)
	methodResp := make([]byte, 2)
	_, err = io.ReadFull(sc1, methodResp)
	require.NoError(err)
	require.Equal([]byte{0x05, 0x02}, methodResp)

	// Subnegotiation: version 1, ulen 2, "u1", plen 2, "p1"
	_, err = sc1.Write([]byte{0x01, 0x02, 'u', '1', 0x02, 'p', '1'})
	require.NoError(err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(sc1, authResp)
	require.NoError(err)
	require.Equal([]byte{0x01, 0x00}, authResp)

	// CONNECT request to 127.0.0.1:echoPort
	portHi := byte(echoAddr.Port >> 8)
	portLo := byte(echoAddr.Port & 0xff)
	_, err = sc1.Write([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, portHi, portLo})
	require.NoError(err)
	connResp := make([]byte, 10)
	_, err = io.ReadFull(sc1, connResp)
	require.NoError(err)
	require.Equal(byte(0x00), connResp[1])

	_, err = sc1.Write([]byte("socks5-echo"))
	require.NoError(err)
	echoed := make([]byte, 11)
	_, err = io.ReadFull(sc1, echoed)
	require.NoError(err)
	require.Equal("socks5-echo", string(echoed))

	// 3. TLS2RawPlugin with ProxyProtocolHeader
	tls2rawPlugin, err := Create(v1.PluginTLS2Raw, PluginContext{Name: "p-tls2raw"}, &v1.TLS2RawPluginOptions{
		LocalAddr: echoAddr.String(),
	})
	require.NoError(err)
	defer tls2rawPlugin.Close()
	require.Equal(v1.PluginTLS2Raw, tls2rawPlugin.Name())

	tc1, tc2 := net.Pipe()
	defer tc1.Close()
	defer tc2.Close()
	ppHdr := &pp.Header{
		Version:           1,
		Command:           pp.PROXY,
		TransportProtocol: pp.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234},
		DestinationAddr:   echoAddr,
	}
	go tls2rawPlugin.Handle(context.Background(), &ConnectionInfo{
		Conn:                tc2,
		UnderlyingConn:      tc2,
		ProxyProtocolHeader: ppHdr,
	})

	tlsCli := tls.Client(tc1, &tls.Config{InsecureSkipVerify: true})
	_ = tlsCli.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = tlsCli.Write([]byte("tls2raw-payload"))
	require.NoError(err)
	// Echo server will first echo the PROXY protocol header then our payload
	rd := bufio.NewReader(tlsCli)
	line, err := rd.ReadString('\n')
	require.NoError(err)
	require.Contains(line, "PROXY TCP4 192.0.2.1")
	payloadBuf := make([]byte, len("tls2raw-payload"))
	_, err = io.ReadFull(rd, payloadBuf)
	require.NoError(err)
	require.Equal("tls2raw-payload", string(payloadBuf))
	_ = tlsCli.Close()

	// 4. VirtualNetPlugin (nil VnetController closes conn cleanly; Close closes tracked conns)
	vnetPlugin, err := Create(v1.PluginVirtualNet, PluginContext{Name: "p-vnet"}, &v1.VirtualNetPluginOptions{})
	require.NoError(err)
	require.Equal(v1.PluginVirtualNet, vnetPlugin.Name())

	vc1, vc2 := net.Pipe()
	defer vc1.Close()
	defer vc2.Close()
	trackedVC := &closeTrackingRWC{ReadWriteCloser: vc1}
	vnetPlugin.Handle(context.Background(), &ConnectionInfo{Conn: trackedVC})
	require.True(trackedVC.closed.Load())

	// Also verify RemoveConn and Close with tracked connections
	vp := vnetPlugin.(*VirtualNetPlugin)
	vc3, vc4 := net.Pipe()
	defer vc3.Close()
	defer vc4.Close()
	trackedVC3 := &closeTrackingRWC{ReadWriteCloser: vc3}
	vp.conns = map[io.ReadWriteCloser]struct{}{trackedVC3: {}}
	require.NoError(vp.Close())
	require.True(trackedVC3.closed.Load())
	vp.RemoveConn(trackedVC3)
}

func TestHTTPProxyAndUnixDomainSocketPlugins(t *testing.T) {
	require := require.New(t)

	// 1. HTTPProxyPlugin forward proxy with BasicAuth
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied-ok"))
	}))
	defer targetSrv.Close()

	hp, err := Create(v1.PluginHTTPProxy, PluginContext{Name: "p-http-proxy"}, &v1.HTTPProxyPluginOptions{
		HTTPUser:     "proxyuser",
		HTTPPassword: "proxypass",
	})
	require.NoError(err)
	defer hp.Close()
	require.Equal(v1.PluginHTTPProxy, hp.Name())

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go hp.Handle(context.Background(), &ConnectionInfo{Conn: c2, UnderlyingConn: c2})

	u, err := url.Parse(targetSrv.URL)
	require.NoError(err)
	_ = c1.SetDeadline(time.Now().Add(3 * time.Second))
	// Send HTTP proxy request with Proxy-Authorization
	// "proxyuser:proxypass" in base64 is "cHJveHl1c2VyOnByb3h5cGFzcw=="
	reqStr := "GET " + targetSrv.URL + "/ HTTP/1.1\r\nHost: " + u.Host + "\r\nProxy-Authorization: Basic cHJveHl1c2VyOnByb3h5cGFzcw==\r\nConnection: close\r\n\r\n"
	_, err = io.WriteString(c1, reqStr)
	require.NoError(err)

	resp, err := http.ReadResponse(bufio.NewReader(c1), nil)
	require.NoError(err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusOK, resp.StatusCode)
	require.Equal("proxied-ok", string(body))

	// 2. UnixDomainSocketPlugin
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	unixLn, err := net.Listen("unix", sockPath)
	require.NoError(err)
	defer unixLn.Close()
	go func() {
		conn, acceptErr := unixLn.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	up, err := Create(v1.PluginUnixDomainSocket, PluginContext{Name: "p-uds"}, &v1.UnixDomainSocketPluginOptions{
		UnixPath: sockPath,
	})
	require.NoError(err)
	defer up.Close()
	require.Equal(v1.PluginUnixDomainSocket, up.Name())

	uc1, uc2 := net.Pipe()
	defer uc1.Close()
	defer uc2.Close()
	go up.Handle(context.Background(), &ConnectionInfo{Conn: uc2, UnderlyingConn: uc2})

	_ = uc1.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = uc1.Write([]byte("uds-echo"))
	require.NoError(err)
	udsBuf := make([]byte, 8)
	_, err = io.ReadFull(uc1, udsBuf)
	require.NoError(err)
	require.Equal("uds-echo", string(udsBuf))
}
