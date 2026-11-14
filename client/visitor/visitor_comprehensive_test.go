package visitor

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	libio "github.com/fatedier/golib/io"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/util"
)

type noopMsgSender struct{}

func (noopMsgSender) Send(msg.Message) error {
	return errors.New("not connected")
}

func newTestMsgConn(c net.Conn) *msg.Conn {
	rw, err := msg.NewReadWriter(c, "")
	if err != nil {
		panic(err)
	}
	return msg.NewConn(c, rw)
}

type closeWithErrorConn struct {
	net.Conn
	closeErr atomic.Value
}

func (c *closeWithErrorConn) CloseWithError(err error) error {
	c.closeErr.Store(err)
	return c.Close()
}

func freeLocalTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func freeLocalUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestVisitorManagerLifecycleAndConcurrency(t *testing.T) {
	require := require.New(t)

	// Hold a port busy initially so v-delayed fails on first UpdateAll and is started by keepVisitorsRunning
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	delayedPort := busyLn.Addr().(*net.TCPAddr).Port
	defer busyLn.Close()

	clientCfg := &v1.ClientCommonConfig{User: "alice"}
	transporter := transport.NewMessageTransporter(noopMsgSender{})

	vm := NewManager(
		context.Background(),
		"run-123",
		clientCfg,
		func() (*msg.Conn, error) {
			return nil, errors.New("not connected")
		},
		transporter,
		nil,
		"json",
	)
	vm.checkInterval = 25 * time.Millisecond
	defer vm.Close()

	// Verify helper methods
	require.Equal("run-123", vm.helper.RunID())
	require.Equal(transporter, vm.helper.MsgTransporter())
	require.Nil(vm.helper.VNetController())
	require.Equal("json", udpPacketCodecFromHelper(vm.helper))

	stcpCfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "v-stcp",
			Type:       "stcp",
			BindAddr:   "127.0.0.1",
			BindPort:   -1,
			ServerName: "server-stcp",
			SecretKey:  "secret",
		},
	}
	delayedCfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "v-delayed",
			Type:       "stcp",
			BindAddr:   "127.0.0.1",
			BindPort:   delayedPort,
			ServerName: "server-delayed",
		},
	}

	vm.UpdateAll([]v1.VisitorConfigurer{stcpCfg, delayedCfg})

	gotCfg, ok := vm.GetVisitorCfg("v-stcp")
	require.True(ok)
	require.Equal("v-stcp", gotCfg.GetBaseConfig().Name)

	// v-delayed should not be in vm.visitors yet because delayedPort is busy
	require.ErrorContains(vm.TransferConn("v-delayed", nil), "not found")

	// Free the busy port so keepVisitorsRunning starts v-delayed while we hammer TransferConn/GetVisitorCfg concurrently
	_ = busyLn.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		for range 20 {
			_, _ = vm.GetVisitorCfg("v-stcp")
			time.Sleep(2 * time.Millisecond)
		}
	})

	require.Eventually(func() bool {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		return vm.TransferConn("v-delayed", c1) == nil
	}, 2*time.Second, 15*time.Millisecond)
	wg.Wait()

	// UpdateAll with modified config and removed visitor
	updatedSTCP := *stcpCfg
	updatedSTCP.SecretKey = "new-secret"
	vm.UpdateAll([]v1.VisitorConfigurer{&updatedSTCP})

	_, ok = vm.GetVisitorCfg("v-delayed")
	require.False(ok)
	gotUpdated, ok := vm.GetVisitorCfg("v-stcp")
	require.True(ok)
	require.Equal("new-secret", gotUpdated.GetBaseConfig().SecretKey)
}

func TestSTCPVisitorEndToEndAndErrorPaths(t *testing.T) {
	require := require.New(t)

	bindPort := freeLocalTCPPort(t)
	secretKey := "stcp-secret-key" //nolint:gosec // test-only secret key

	var serverErrResp atomic.Value
	serverErrResp.Store("")

	connectServer := func() (*msg.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			mc := newTestMsgConn(c2)
			rawMsg, err := mc.ReadMsg()
			if err != nil {
				return
			}
			req, ok := rawMsg.(*msg.NewVisitorConn)
			if !ok {
				return
			}
			errText := serverErrResp.Load().(string)
			_ = mc.WriteMsg(&msg.NewVisitorConnResp{
				ProxyName: req.ProxyName,
				Error:     errText,
			})
			if errText != "" {
				return
			}
			// Verify SignKey matches SecretKey and Timestamp
			if util.GetAuthKey(secretKey, req.Timestamp) != req.SignKey {
				return
			}

			var rwc io.ReadWriteCloser = mc
			if req.UseEncryption {
				var encErr error
				rwc, encErr = libio.WithEncryption(rwc, []byte(secretKey))
				if encErr != nil {
					return
				}
			}
			if req.UseCompression {
				var recycle func()
				rwc, recycle = libio.WithCompressionFromPool(rwc)
				defer recycle()
			}
			_, _ = io.Copy(rwc, rwc)
		}()
		return newTestMsgConn(c1), nil
	}

	clientCfg := &v1.ClientCommonConfig{User: "user1"}
	vm := NewManager(context.Background(), "run-stcp", clientCfg, connectServer, nil, nil)
	defer vm.Close()

	stcpCfg := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "stcp-e2e",
			Type:       "stcp",
			BindAddr:   "127.0.0.1",
			BindPort:   bindPort,
			ServerUser: "srvuser",
			ServerName: "ssh",
			SecretKey:  secretKey,
			Transport: v1.VisitorTransport{
				UseEncryption:  true,
				UseCompression: true,
			},
		},
	}

	v, err := NewVisitor(context.Background(), stcpCfg, clientCfg, vm.helper)
	require.NoError(err)
	require.NoError(v.Run())
	defer v.Close()

	// 1. Dial local TCP port and verify encrypted + compressed echo round-trip
	conn, err := net.DialTimeout("tcp", (&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: bindPort}).String(), 2*time.Second)
	require.NoError(err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	payload := []byte("hello encrypted compressed stcp visitor")
	_, err = conn.Write(payload)
	require.NoError(err)

	reply := make([]byte, len(payload))
	_, err = io.ReadFull(conn, reply)
	require.NoError(err)
	require.Equal(payload, reply)

	// 2. Server returns error in NewVisitorConnResp -> CloseWithError is invoked on internal connection
	serverErrResp.Store("proxy offline")
	u1, u2 := net.Pipe()
	defer u1.Close()
	defer u2.Close()
	errConn := &closeWithErrorConn{Conn: u1}
	require.NoError(v.AcceptConn(errConn))

	require.Eventually(func() bool {
		return errConn.closeErr.Load() != nil
	}, 2*time.Second, 10*time.Millisecond)
	require.ErrorContains(errConn.closeErr.Load().(error), "proxy offline")
}

func TestSUDPVisitorEndToEnd(t *testing.T) {
	require := require.New(t)

	udpPort := freeLocalUDPPort(t)
	secretKey := "sudp-secret"

	connectServer := func() (*msg.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer c2.Close()
			mc := newTestMsgConn(c2)
			rawMsg, err := mc.ReadMsg()
			if err != nil {
				return
			}
			req, ok := rawMsg.(*msg.NewVisitorConn)
			if !ok {
				return
			}
			_ = mc.WriteMsg(&msg.NewVisitorConnResp{ProxyName: req.ProxyName})

			rw, err := msg.NewUDPPacketReadWriter(mc, "", "")
			if err != nil {
				return
			}
			pktConn := msg.NewConn(mc, rw)
			// Send a heartbeat Ping first
			_ = pktConn.WriteMsg(&msg.Ping{})

			inMsg, err := pktConn.ReadMsg()
			if err != nil {
				return
			}
			udpPkt, ok := inMsg.(*msg.UDPPacket)
			if !ok {
				return
			}
			_ = pktConn.WriteMsg(&msg.UDPPacket{
				Content:    append([]byte("ack:"), udpPkt.Content...),
				LocalAddr:  udpPkt.LocalAddr,
				RemoteAddr: udpPkt.RemoteAddr,
			})
		}()
		return newTestMsgConn(c1), nil
	}

	clientCfg := &v1.ClientCommonConfig{
		User:          "u1",
		UDPPacketSize: 1500,
	}
	vm := NewManager(context.Background(), "run-sudp", clientCfg, connectServer, nil, nil)
	defer vm.Close()

	sudpCfg := &v1.SUDPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "sudp-e2e",
			Type:       "sudp",
			BindAddr:   "127.0.0.1",
			BindPort:   udpPort,
			ServerName: "dns",
			SecretKey:  secretKey,
		},
	}

	v, err := NewVisitor(context.Background(), sudpCfg, clientCfg, vm.helper)
	require.NoError(err)
	require.NoError(v.Run())
	defer v.Close()

	// Send a UDP datagram to the SUDPVisitor local UDP port and read the echoed response
	clientUDP, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udpPort})
	require.NoError(err)
	defer clientUDP.Close()
	_ = clientUDP.SetDeadline(time.Now().Add(3 * time.Second))

	_, err = clientUDP.Write([]byte("ping-udp"))
	require.NoError(err)

	buf := make([]byte, 64)
	n, err := clientUDP.Read(buf)
	require.NoError(err)
	require.Equal("ack:ping-udp", string(buf[:n]))
}

type fakeTunnelSession struct {
	mu     sync.Mutex
	openFn func(context.Context) (net.Conn, error)
	closed atomic.Bool
}

func (f *fakeTunnelSession) setOpenFn(fn func(context.Context) (net.Conn, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openFn = fn
}

func (f *fakeTunnelSession) Init(_ context.Context, _ *net.UDPConn, _ *net.UDPAddr) error {
	return nil
}

func (f *fakeTunnelSession) OpenConn(ctx context.Context) (net.Conn, error) {
	f.mu.Lock()
	fn := f.openFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return nil, ErrNoTunnelSession
}

func (f *fakeTunnelSession) Close() {
	f.closed.Store(true)
}

func TestXTCPVisitorTunnelFallbackAndSessions(t *testing.T) {
	require := require.New(t)

	// 1. KCPTunnelSession and QUICTunnelSession return ErrNoTunnelSession when uninitialized
	kcpSess := NewKCPTunnelSession()
	_, err := kcpSess.OpenConn(context.Background())
	require.ErrorIs(err, ErrNoTunnelSession)
	kcpSess.Close()

	clientCfg := &v1.ClientCommonConfig{}
	quicSess := NewQUICTunnelSession(clientCfg)
	_, err = quicSess.OpenConn(context.Background())
	require.ErrorIs(err, ErrNoTunnelSession)
	quicSess.Close()

	// 2. XTCPVisitor with active tunnel session forwards data
	var transferredTo atomic.Value
	transferredConnCh := make(chan net.Conn, 1)

	vm := NewManager(context.Background(), "run-xtcp", clientCfg, nil, transport.NewMessageTransporter(noopMsgSender{}), nil)
	vm.helper = &visitorHelperImpl{
		msgTransporter: transport.NewMessageTransporter(noopMsgSender{}),
		transferConnFn: func(name string, conn net.Conn) error {
			transferredTo.Store(name)
			transferredConnCh <- conn
			return nil
		},
		runID: "run-xtcp",
	}
	defer vm.Close()

	xtcpCfg := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "xtcp-main",
			Type:       "xtcp",
			BindPort:   -1,
			ServerName: "p2p-ssh",
			SecretKey:  "xtcp-key",
		},
		Protocol:          "kcp",
		KeepTunnelOpen:    true,
		MaxRetriesAnHour:  0, // tests non-positive guard
		MinRetryInterval:  0, // tests non-positive guard
		FallbackTo:        "stcp-backup",
		FallbackTimeoutMs: 60,
	}

	rawV, err := NewVisitor(context.Background(), xtcpCfg, clientCfg, vm.helper)
	require.NoError(err)
	xv := rawV.(*XTCPVisitor)
	fakeSess := &fakeTunnelSession{
		openFn: func(_ context.Context) (net.Conn, error) {
			t1, t2 := net.Pipe()
			go func() {
				defer t2.Close()
				_, _ = io.Copy(t2, t2)
			}()
			return t1, nil
		},
	}
	xv.session = fakeSess
	require.NoError(xv.Run())
	defer xv.Close()

	u1, u2 := net.Pipe()
	defer u1.Close()
	defer u2.Close()
	_ = u2.SetDeadline(time.Now().Add(2 * time.Second))
	require.NoError(xv.AcceptConn(u1))

	_, err = u2.Write([]byte("xtcp-direct"))
	require.NoError(err)
	buf := make([]byte, 11)
	_, err = io.ReadFull(u2, buf)
	require.NoError(err)
	require.Equal("xtcp-direct", string(buf))
	_ = u1.Close()
	_ = u2.Close()

	// 3. When tunnel OpenConn returns ErrNoTunnelSession until FallbackTimeoutMs expires, XTCPVisitor transfers conn to FallbackTo
	fakeSess.setOpenFn(func(_ context.Context) (net.Conn, error) {
		return nil, ErrNoTunnelSession
	})

	f1, f2 := net.Pipe()
	defer f1.Close()
	defer f2.Close()
	require.NoError(xv.AcceptConn(f1))

	select {
	case fallbackConn := <-transferredConnCh:
		require.Equal("stcp-backup", transferredTo.Load())
		_ = fallbackConn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for XTCPVisitor fallback transfer")
	}
}
