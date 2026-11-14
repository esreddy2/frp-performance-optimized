package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	libio "github.com/fatedier/golib/io"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
)

// TestSTCPProxyUsesHop2EncryptionKey verifies that STCP proxies use
// pxy.encryptionKey as the decryption key for wrapping work connections matching
// the server's Hop-2 encryption in server/proxy/proxy.go:371.
func TestSTCPProxyUsesHop2EncryptionKey(t *testing.T) {
	require := require.New(t)

	const proxySecret = "stcp-custom-secret-key-1234" //nolint:gosec // test-only secret
	const clientToken = "global-client-token-5678"

	// Local TCP service listener
	localLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	t.Cleanup(func() { _ = localLn.Close() })
	localPort := localLn.Addr().(*net.TCPAddr).Port

	cfg := &v1.STCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "stcp-test",
			Type: "stcp",
			Transport: v1.ProxyTransport{
				UseEncryption: true,
			},
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   "127.0.0.1",
				LocalPort: localPort,
			},
		},
		Secretkey: proxySecret,
	}

	base := &BaseProxy{
		baseCfg:       &cfg.ProxyBaseConfig,
		encryptionKey: []byte(clientToken),
		xl:            xlog.New(),
		ctx:           context.Background(),
	}

	pxy := NewSTCPProxy(base, cfg)
	require.NotNil(pxy)

	// --- 1. Positive case: peer encrypted with clientToken (Hop 2 from FRPS) succeeds through InWorkConn ---
	clientWorkConn, serverPeerConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientWorkConn.Close()
		_ = serverPeerConn.Close()
	})

	// Invoke InWorkConn directly on the proxy
	go pxy.InWorkConn(clientWorkConn, &msg.StartWorkConn{})

	localConn, err := localLn.Accept()
	require.NoError(err)
	t.Cleanup(func() { _ = localConn.Close() })

	wrappedPeer, err := libio.WithEncryption(serverPeerConn, []byte(clientToken))
	require.NoError(err)

	testPayload := []byte("hello stcp encrypted stream")
	go func() {
		_, _ = wrappedPeer.Write(testPayload)
	}()

	recvBuf := make([]byte, len(testPayload))
	_, err = io.ReadFull(localConn, recvBuf)
	require.NoError(err)
	require.Equal(testPayload, recvBuf)

	// Bi-directional check: write from local service, verify decrypted on peer
	replyPayload := []byte("stcp reply to visitor")
	go func() {
		_, _ = localConn.Write(replyPayload)
	}()

	replyBuf := make([]byte, len(replyPayload))
	_, err = io.ReadFull(wrappedPeer, replyBuf)
	require.NoError(err)
	require.Equal(replyPayload, replyBuf)

	// --- 2. Negative case: peer encrypted with wrong key fails through InWorkConn ---
	clientWorkConn2, serverPeerConn2 := net.Pipe()
	t.Cleanup(func() {
		_ = clientWorkConn2.Close()
		_ = serverPeerConn2.Close()
	})

	go pxy.InWorkConn(clientWorkConn2, &msg.StartWorkConn{})

	localConn2, err := localLn.Accept()
	require.NoError(err)
	t.Cleanup(func() { _ = localConn2.Close() })

	// Peer encrypts with wrong key (proxySecret instead of clientToken)
	wrappedPeerWrong, err := libio.WithEncryption(serverPeerConn2, []byte(proxySecret))
	require.NoError(err)

	go func() {
		_, _ = wrappedPeerWrong.Write([]byte("unauthorized stream with wrong key"))
	}()

	// Decryption in pxy.InWorkConn must fail because proxy uses pxy.encryptionKey, closing the connection
	_ = localConn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	wrongBuf := make([]byte, 64)
	_, err = io.ReadFull(localConn2, wrongBuf)
	require.Error(err, "stream encrypted with wrong key must fail decryption in STCPProxy.InWorkConn")
}

// TestSUDPProxyUsesHop2EncryptionKey verifies that SUDP proxies use
// pxy.encryptionKey as the decryption key for wrapping work connections matching
// the server's Hop-2 encryption in server/proxy/udp.go:399.
func TestSUDPProxyUsesHop2EncryptionKey(t *testing.T) {
	require := require.New(t)

	const proxySecret = "sudp-custom-secret-key-1234" //nolint:gosec // test-only secret
	const clientToken = "global-client-token-5678"

	// Local UDP service listener
	localUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(err)
	t.Cleanup(func() { _ = localUDP.Close() })
	localPort := localUDP.LocalAddr().(*net.UDPAddr).Port

	cfg := &v1.SUDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "sudp-test",
			Type: "sudp",
			Transport: v1.ProxyTransport{
				UseEncryption: true,
			},
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   "127.0.0.1",
				LocalPort: localPort,
			},
		},
		Secretkey: proxySecret,
	}

	base := &BaseProxy{
		baseCfg:       &cfg.ProxyBaseConfig,
		encryptionKey: []byte(clientToken),
		clientCfg:     &v1.ClientCommonConfig{UDPPacketSize: 1500},
		xl:            xlog.New(),
		ctx:           context.Background(),
	}

	pxy := &SUDPProxy{
		BaseProxy: base,
		cfg:       cfg,
	}
	require.NoError(pxy.Run())
	t.Cleanup(pxy.Close)

	// --- 1. Positive case: peer encrypted with clientToken (Hop 2 from FRPS) succeeds through InWorkConn ---
	clientWorkConn, serverPeerConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientWorkConn.Close()
		_ = serverPeerConn.Close()
	})

	// Invoke InWorkConn directly on the proxy
	go pxy.InWorkConn(clientWorkConn, nil)

	// Peer side wraps connection with clientToken (matching Hop-2 encryption from FRPS)
	wrappedPeer, err := libio.WithEncryption(serverPeerConn, []byte(clientToken))
	require.NoError(err)

	peerConn := netpkg.WrapReadWriteCloserToConn(wrappedPeer, serverPeerConn)
	peerRW, err := msg.NewUDPPacketReadWriter(peerConn, "", "")
	require.NoError(err)
	peerMsgConn := msg.NewConn(peerConn, peerRW)

	testPayload := []byte("hello sudp encrypted stream")
	udpPkt := &msg.UDPPacket{
		Content:    testPayload,
		LocalAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18888},
		RemoteAddr: localUDP.LocalAddr().(*net.UDPAddr),
	}
	err = peerMsgConn.WriteMsg(udpPkt)
	require.NoError(err)

	// Verify packet arrives at local UDP service
	buf := make([]byte, 1024)
	_ = localUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := localUDP.ReadFromUDP(buf)
	require.NoError(err)
	require.Equal(testPayload, buf[:n])

	// --- 2. Negative case: peer encrypted with wrong key fails through InWorkConn ---
	clientWorkConn2, serverPeerConn2 := net.Pipe()
	t.Cleanup(func() {
		_ = clientWorkConn2.Close()
		_ = serverPeerConn2.Close()
	})

	go pxy.InWorkConn(clientWorkConn2, nil)

	// Peer side encrypts with wrong key (proxySecret instead of clientToken)
	wrappedPeerWrong, err := libio.WithEncryption(serverPeerConn2, []byte(proxySecret))
	require.NoError(err)

	peerConnWrong := netpkg.WrapReadWriteCloserToConn(wrappedPeerWrong, serverPeerConn2)
	peerRWWrong, err := msg.NewUDPPacketReadWriter(peerConnWrong, "", "")
	require.NoError(err)
	peerMsgConnWrong := msg.NewConn(peerConnWrong, peerRWWrong)

	_ = peerMsgConnWrong.WriteMsg(&msg.UDPPacket{
		Content:    []byte("unauthorized sudp packet"),
		LocalAddr:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 19999},
		RemoteAddr: localUDP.LocalAddr().(*net.UDPAddr),
	})

	// Packet should NOT arrive because InWorkConn fails to decrypt using pxy.encryptionKey
	_ = localUDP.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, _, err = localUDP.ReadFromUDP(buf)
	require.Error(err, "packet encrypted with wrong key must fail decryption in SUDPProxy.InWorkConn")
}
