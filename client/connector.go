// Copyright 2023 The frp Authors
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

package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	libnet "github.com/fatedier/golib/net"
	fmux "github.com/fatedier/yamux"
	quic "github.com/quic-go/quic-go"
	"github.com/samber/lo"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
)

// Connector is an interface for establishing connections to the server.
type Connector interface {
	Open() error
	Connect() (net.Conn, error)
	Close() error
}

type MessageConnector interface {
	Connect() (*msg.Conn, error)
	Close() error
}

type messageConnector struct {
	connector    Connector
	wireProtocol string
}

func newMessageConnector(connector Connector, wireProtocol string) *messageConnector {
	return &messageConnector{
		connector:    connector,
		wireProtocol: wireProtocol,
	}
}

func (c *messageConnector) Connect() (*msg.Conn, error) {
	conn, err := c.connector.Connect()
	if err != nil {
		return nil, err
	}
	if err = wire.WriteMagicIfV2(conn, c.wireProtocol); err != nil {
		conn.Close()
		return nil, err
	}
	rw, err := msg.NewReadWriter(conn, c.wireProtocol)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return msg.NewConn(conn, rw), nil
}

func (c *messageConnector) Close() error {
	return c.connector.Close()
}

// defaultConnectorImpl is the default implementation of Connector for normal frpc.
type defaultConnectorImpl struct {
	ctx context.Context
	cfg *v1.ClientCommonConfig

	mu         sync.Mutex
	muxSession *fmux.Session
	quicConn   *quic.Conn
}

func NewConnector(ctx context.Context, cfg *v1.ClientCommonConfig) Connector {
	return &defaultConnectorImpl{
		ctx: ctx,
		cfg: cfg,
	}
}

// clientTLSConfig builds the TLS configuration used to reach frps.
//
// It returns nil when the transport does not use TLS at all. The wss and quic
// transports always run over TLS, so their material is honored even when
// transport.tls.enable is false.
func (c *defaultConnectorImpl) clientTLSConfig() (*tls.Config, error) {
	tlsCfg := c.cfg.Transport.TLS
	if !lo.FromPtr(tlsCfg.Enable) && !c.cfg.Transport.UsesImplicitTLS() {
		return nil, nil
	}

	sn := tlsCfg.ServerName
	if sn == "" {
		sn = c.cfg.ServerAddr
	}
	return transport.NewClientTLSConfigWithSystemCA(
		tlsCfg.CertFile,
		tlsCfg.KeyFile,
		tlsCfg.TrustedCaFile,
		sn,
		tlsCfg.UseSystemCa)
}

// Open opens an underlying connection to the server.
// The underlying connection is either a TCP connection or a QUIC connection.
// After the underlying connection is established, you can call Connect() to get a stream.
// If TCPMux isn't enabled, the underlying connection is nil, you will get a new real TCP connection every time you call Connect().
func (c *defaultConnectorImpl) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	xl := xlog.FromContextSafe(c.ctx)

	// special for quic
	if strings.EqualFold(c.cfg.Transport.Protocol, "quic") {
		// Close any previously opened QUIC connection before replacing it.
		if c.quicConn != nil {
			_ = c.quicConn.CloseWithError(0, "")
			c.quicConn = nil
		}

		tlsConfig, err := c.clientTLSConfig()
		if err != nil {
			xl.Warnf("fail to build tls configuration, err: %v", err)
			return err
		}
		if tlsConfig == nil {
			// QUIC always runs over TLS.
			tlsCfg := c.cfg.Transport.TLS
			sn := tlsCfg.ServerName
			if sn == "" {
				sn = c.cfg.ServerAddr
			}
			tlsConfig, err = transport.NewClientTLSConfigWithSystemCA(
				tlsCfg.CertFile,
				tlsCfg.KeyFile,
				tlsCfg.TrustedCaFile,
				sn,
				tlsCfg.UseSystemCa,
			)
			if err != nil {
				xl.Warnf("fail to build tls configuration, err: %v", err)
				return err
			}
		}
		tlsConfig.NextProtos = []string{"frp"}

		quicConfig := &quic.Config{
			MaxIdleTimeout:             time.Duration(c.cfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:         int64(c.cfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:            time.Duration(c.cfg.Transport.QUIC.KeepalivePeriod) * time.Second,
			EnableDatagrams:            lo.FromPtr(c.cfg.Transport.QUIC.EnableDatagrams),
			MaxStreamReceiveWindow:     1 << 20,
			MaxConnectionReceiveWindow: 4 << 20,
		}
		if lo.FromPtr(c.cfg.Transport.QUIC.Enable0RTT) {
			// frp does not use QUIC 0-RTT. The option only enables the
			// address validation token cache, which lets the server skip
			// the address validation Retry on a reconnect. The connection
			// is opened with quic.DialAddr, never with quic.DialAddrEarly:
			// the first message frp sends on a QUIC connection carries the
			// client's credential, and 0-RTT early data is replayable.
			quicConfig.TokenStore = quic.NewLRUTokenStore(100, 10)
		}
		serverAddr := net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort))

		dialTimeout := time.Duration(c.cfg.Transport.DialServerTimeout) * time.Second
		dialCtx := c.ctx
		var cancel context.CancelFunc
		if dialTimeout > 0 {
			dialCtx, cancel = context.WithTimeout(c.ctx, dialTimeout)
		}
		if cancel != nil {
			defer cancel()
		}

		if localIP := c.cfg.Transport.ConnectServerLocalIP; localIP != "" {
			ip := net.ParseIP(localIP)
			if ip == nil {
				return fmt.Errorf("invalid ConnectServerLocalIP %q", localIP)
			}
			udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
			if err != nil {
				return fmt.Errorf("resolve quic server %s: %w", serverAddr, err)
			}
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip, Port: 0})
			if err != nil {
				return fmt.Errorf("bind quic local address %s: %w", localIP, err)
			}
			tr := &quic.Transport{Conn: udpConn}
			conn, err := tr.Dial(dialCtx, udpAddr, tlsConfig, quicConfig)
			if err != nil {
				tr.Close()
				return fmt.Errorf("dial quic server %s: %w (the server must listen for quic on udp port %d: set quicBindPort in the server config)",
					serverAddr, err, c.cfg.ServerPort)
			}
			go func() {
				<-conn.Context().Done()
				_ = udpConn.Close()
			}()
			c.quicConn = conn
			return nil
		}

		conn, err := quic.DialAddr(
			dialCtx,
			serverAddr,
			tlsConfig, quicConfig)
		if err != nil {
			return fmt.Errorf("dial quic server %s: %w (the server must listen for quic on udp port %d: set quicBindPort in the server config)",
				serverAddr, err, c.cfg.ServerPort)
		}
		c.quicConn = conn
		return nil
	}

	// Close any previously created yamux session before replacing it.
	if c.muxSession != nil {
		_ = c.muxSession.Close()
		c.muxSession = nil
	}

	if !lo.FromPtr(c.cfg.Transport.TCPMux) {
		return nil
	}

	conn, err := c.realConnect()
	if err != nil {
		return err
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = time.Duration(c.cfg.Transport.TCPMuxKeepaliveInterval) * time.Second
	// Use trace level for yamux logs
	fmuxCfg.LogOutput = xlog.NewTraceWriter(xl)
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	session, err := fmux.Client(conn, fmuxCfg)
	if err != nil {
		conn.Close()
		return err
	}
	c.muxSession = session
	return nil
}

// Connect returns a stream from the underlying connection, or a new TCP connection if TCPMux isn't enabled.
func (c *defaultConnectorImpl) Connect() (net.Conn, error) {
	c.mu.Lock()
	quicConn := c.quicConn
	muxSession := c.muxSession
	c.mu.Unlock()

	if quicConn != nil {
		stream, err := quicConn.OpenStreamSync(c.ctx)
		if err != nil {
			return nil, err
		}
		return netpkg.QuicStreamToNetConn(stream, quicConn), nil
	} else if muxSession != nil {
		stream, err := muxSession.OpenStream()
		if err != nil {
			return nil, err
		}
		return stream, nil
	}

	return c.realConnect()
}

func (c *defaultConnectorImpl) realConnect() (net.Conn, error) {
	xl := xlog.FromContextSafe(c.ctx)
	tlsConfig, err := c.clientTLSConfig()
	if err != nil {
		xl.Warnf("fail to build tls configuration, err: %v", err)
		return nil, err
	}

	proxyType, addr, auth, err := libnet.ParseProxyURL(c.cfg.Transport.ProxyURL)
	if err != nil {
		xl.Errorf("fail to parse proxy url: %v", err)
		return nil, err
	}
	dialOptions := []libnet.DialOption{}
	protocol := c.cfg.Transport.Protocol
	switch protocol {
	case "websocket":
		protocol = "tcp"
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{Hook: netpkg.DialHookWebsocket(protocol, ""), Priority: 15}))
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{
			Hook:     netpkg.DialHookCustomTLSHeadByte(tlsConfig != nil, lo.FromPtr(c.cfg.Transport.TLS.DisableCustomTLSFirstByte)),
			Priority: 20,
		}))
		dialOptions = append(dialOptions, libnet.WithTLSConfig(tlsConfig))
	case "wss":
		protocol = "tcp"
		dialOptions = append(dialOptions, libnet.WithTLSConfigAndPriority(100, tlsConfig))
		// Make sure that if it is wss, the websocket hook is executed after the tls hook.
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{Hook: netpkg.DialHookWebsocket(protocol, tlsConfig.ServerName), Priority: 110}))
	default:
		dialOptions = append(dialOptions, libnet.WithAfterHook(libnet.AfterHook{
			Hook: netpkg.DialHookCustomTLSHeadByte(tlsConfig != nil, lo.FromPtr(c.cfg.Transport.TLS.DisableCustomTLSFirstByte)),
		}))
		dialOptions = append(dialOptions, libnet.WithTLSConfig(tlsConfig))
	}

	if c.cfg.Transport.ConnectServerLocalIP != "" {
		dialOptions = append(dialOptions, libnet.WithLocalAddr(c.cfg.Transport.ConnectServerLocalIP))
	}
	dialOptions = append(dialOptions,
		libnet.WithProtocol(protocol),
		libnet.WithTimeout(time.Duration(c.cfg.Transport.DialServerTimeout)*time.Second),
		libnet.WithKeepAlive(time.Duration(c.cfg.Transport.DialServerKeepAlive)*time.Second),
		libnet.WithProxy(proxyType, addr),
		libnet.WithProxyAuth(auth),
	)
	conn, err := libnet.DialContext(
		c.ctx,
		net.JoinHostPort(c.cfg.ServerAddr, strconv.Itoa(c.cfg.ServerPort)),
		dialOptions...,
	)
	if err == nil {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if derr := tcpConn.SetNoDelay(true); derr != nil {
				conn.Close()
				return nil, fmt.Errorf("set tcp no delay: %w", derr)
			}
			if toptErr := applyTCPSendQueueOpts(tcpConn, c.cfg.Transport.TCPNotSentLowat, c.cfg.Transport.TCPSendBuffer); toptErr != nil {
				conn.Close()
				return nil, fmt.Errorf("apply tcp send queue options: %w", toptErr)
			}
		}
	}
	return conn, err
}

func (c *defaultConnectorImpl) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	if c.quicConn != nil {
		if err := c.quicConn.CloseWithError(0, ""); err != nil {
			errs = append(errs, err)
		}
		c.quicConn = nil
	}
	if c.muxSession != nil {
		if err := c.muxSession.Close(); err != nil {
			errs = append(errs, err)
		}
		c.muxSession = nil
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
