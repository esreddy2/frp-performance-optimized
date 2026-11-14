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

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"

	"github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func TestParseExecPayload(t *testing.T) {
	payload := cryptossh.Marshal(&execPayload{Command: "tcp --remote_port 6000"})

	got, ok := parseExecPayload(payload)

	require.True(t, ok)
	require.Equal(t, "tcp --remote_port 6000", got)
}

func TestParseExecPayloadRejectsMalformedPayloads(t *testing.T) {
	overflowLength := make([]byte, 5)
	binary.BigEndian.PutUint32(overflowLength[:4], ^uint32(0))

	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{
			name:    "empty",
			payload: nil,
		},
		{
			name:    "short length prefix",
			payload: []byte{0, 0, 0},
		},
		{
			name:    "declared length exceeds remaining payload",
			payload: []byte{0, 0, 0, 2, 'x'},
		},
		{
			name:    "overflow length",
			payload: overflowLength,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				got string
				ok  bool
			)
			require.NotPanics(t, func() {
				got, ok = parseExecPayload(tc.payload)
			})
			require.False(t, ok)
			require.Empty(t, got)
		})
	}
}

type trackingChannel struct {
	active     atomic.Int32
	concurrent atomic.Bool
}

func (c *trackingChannel) Read([]byte) (int, error) { return 0, io.EOF }

func (c *trackingChannel) Write(p []byte) (int, error) {
	if c.active.Add(1) != 1 {
		c.concurrent.Store(true)
	}
	time.Sleep(time.Millisecond)
	c.active.Add(-1)
	return len(p), nil
}

func (c *trackingChannel) Close() error                                   { return nil }
func (c *trackingChannel) CloseWrite() error                              { return nil }
func (c *trackingChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (c *trackingChannel) Stderr() io.ReadWriter                          { return nil }

func TestWriteToClientSerializesChannelWrites(t *testing.T) {
	channel := &trackingChannel{}
	s := &TunnelServer{firstChannel: channel}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			s.writeToClient("message")
		})
	}
	close(start)
	wg.Wait()

	if channel.concurrent.Load() {
		t.Fatal("channel writes were concurrent")
	}
}

type fakeConnMetadata struct{}

func (fakeConnMetadata) User() string          { return "v0" }
func (fakeConnMetadata) SessionID() []byte     { return []byte("sid") }
func (fakeConnMetadata) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (fakeConnMetadata) ServerVersion() []byte { return []byte("SSH-2.0-frp") }
func (fakeConnMetadata) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
}

func (fakeConnMetadata) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2200}
}

func generateTestSSHPublicKey(t *testing.T) cryptossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := cryptossh.NewPublicKey(pub)
	require.NoError(t, err)
	return sshPub
}

func TestGatewayKeyManagementAndAuthorizedKeys(t *testing.T) {
	tmpDir := t.TempDir()
	peerLn := netpkg.NewInternalListener()
	defer peerLn.Close()

	// 1. AutoGenPrivateKeyPath creates key file on first run and reuses it on second run.
	autoKeyPath := filepath.Join(tmpDir, "autogen_id_rsa")
	gw1, err := NewGateway(v1.SSHTunnelGateway{
		BindPort:              0,
		AutoGenPrivateKeyPath: autoKeyPath,
	}, "127.0.0.1", peerLn)
	require.NoError(t, err)
	require.True(t, gw1.sshConfig.NoClientAuth)
	require.NoError(t, gw1.Close())

	savedKeyBytes, err := os.ReadFile(autoKeyPath)
	require.NoError(t, err)
	require.NotEmpty(t, savedKeyBytes)

	gw2, err := NewGateway(v1.SSHTunnelGateway{
		BindPort:              0,
		AutoGenPrivateKeyPath: autoKeyPath,
	}, "127.0.0.1", peerLn)
	require.NoError(t, err)
	require.NoError(t, gw2.Close())

	reloadedKeyBytes, err := os.ReadFile(autoKeyPath)
	require.NoError(t, err)
	require.Equal(t, savedKeyBytes, reloadedKeyBytes)

	// 2. AuthorizedKeysFile parses multiple keys, comments, and trailing blank/comment lines, and enforces PublicKeyCallback.
	aliceKey := generateTestSSHPublicKey(t)
	bobKey := generateTestSSHPublicKey(t)
	unknownKey := generateTestSSHPublicKey(t)

	authKeysFile := filepath.Join(tmpDir, "authorized_keys")
	authContent := fmt.Sprintf("# leading comment\n\n%s alice\n# middle comment\n%s bob\n\n# trailing comment\n\n",
		string(cryptossh.MarshalAuthorizedKey(aliceKey))[:len(cryptossh.MarshalAuthorizedKey(aliceKey))-1],
		string(cryptossh.MarshalAuthorizedKey(bobKey))[:len(cryptossh.MarshalAuthorizedKey(bobKey))-1],
	)
	require.NoError(t, os.WriteFile(authKeysFile, []byte(authContent), 0o600))

	privKeyPath := filepath.Join(tmpDir, "explicit_key")
	privBytes, err := transport.NewRandomPrivateKey()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(privKeyPath, privBytes, 0o600))

	gwAuth, err := NewGateway(v1.SSHTunnelGateway{
		BindPort:           0,
		PrivateKeyFile:     privKeyPath,
		AuthorizedKeysFile: authKeysFile,
	}, "127.0.0.1", peerLn)
	require.NoError(t, err)
	defer gwAuth.Close()
	require.False(t, gwAuth.sshConfig.NoClientAuth)

	perms, err := gwAuth.sshConfig.PublicKeyCallback(fakeConnMetadata{}, aliceKey)
	require.NoError(t, err)
	require.Equal(t, "alice", perms.Extensions["user"])

	perms, err = gwAuth.sshConfig.PublicKeyCallback(fakeConnMetadata{}, bobKey)
	require.NoError(t, err)
	require.Equal(t, "bob", perms.Extensions["user"])

	_, err = gwAuth.sshConfig.PublicKeyCallback(fakeConnMetadata{}, unknownKey)
	require.ErrorContains(t, err, "unknown public key")

	// Comment-only authorized_keys file succeeds with an empty key map.
	commentOnlyFile := filepath.Join(tmpDir, "comment_only_keys")
	require.NoError(t, os.WriteFile(commentOnlyFile, []byte("# no keys yet\n\n"), 0o600))
	emptyMap, err := loadAuthorizedKeysFromFile(commentOnlyFile)
	require.NoError(t, err)
	require.Empty(t, emptyMap)

	// 3. Invalid private key or malformed authorized_keys returns error.
	badKeyFile := filepath.Join(tmpDir, "bad_key")
	require.NoError(t, os.WriteFile(badKeyFile, []byte("not-a-private-key"), 0o600))
	_, err = NewGateway(v1.SSHTunnelGateway{BindPort: 0, PrivateKeyFile: badKeyFile}, "127.0.0.1", peerLn)
	require.Error(t, err)

	badAuthFile := filepath.Join(tmpDir, "bad_auth")
	require.NoError(t, os.WriteFile(badAuthFile, []byte("invalid-ssh-pubkey-line\n"), 0o600))
	_, err = loadAuthorizedKeysFromFile(badAuthFile)
	require.Error(t, err)
}

func TestParseClientAndProxyConfigurer(t *testing.T) {
	s := &TunnelServer{}
	forwardAddr := &tcpipForward{Host: "127.0.0.1", Port: 9000}

	t.Run("parses supported proxy types and flags", func(t *testing.T) {
		clientCfg, pc, help, err := s.parseClientAndProxyConfigurer(
			forwardAddr,
			"tcp --proxy_name my-tcp --remote_port 6000 --user devuser --token tok123",
		)
		require.NoError(t, err)
		require.Empty(t, help)
		require.Equal(t, "devuser", clientCfg.User)
		require.Equal(t, "tok123", clientCfg.Auth.Token)
		tcpCfg, ok := pc.(*v1.TCPProxyConfig)
		require.True(t, ok)
		require.Equal(t, "my-tcp", tcpCfg.Name)
		require.Equal(t, 6000, tcpCfg.RemotePort)
	})

	t.Run("auto-generates proxy name when omitted", func(t *testing.T) {
		_, pc, _, err := s.parseClientAndProxyConfigurer(
			forwardAddr,
			"http --custom_domain example.com",
		)
		require.NoError(t, err)
		require.Contains(t, pc.GetBaseConfig().Name, "sshtunnel-http-")
	})

	t.Run("returns help message on --help flag", func(t *testing.T) {
		_, _, help, err := s.parseClientAndProxyConfigurer(forwardAddr, "tcp --help")
		require.ErrorIs(t, err, flag.ErrHelp)
		require.NotEmpty(t, help)
	})

	t.Run("rejects unsupported proxy type and unknown flags", func(t *testing.T) {
		_, _, _, err := s.parseClientAndProxyConfigurer(forwardAddr, "udp --remote_port 6000")
		require.ErrorContains(t, err, "invalid proxy type")

		_, _, _, err = s.parseClientAndProxyConfigurer(forwardAddr, "tcp --nonexistent_flag 1")
		require.Error(t, err)
	})
}

type fakeNewChannel struct {
	ch   cryptossh.Channel
	reqs <-chan *cryptossh.Request
}

func (f *fakeNewChannel) Accept() (cryptossh.Channel, <-chan *cryptossh.Request, error) {
	return f.ch, f.reqs, nil
}

func (f *fakeNewChannel) Reject(cryptossh.RejectionReason, string) error { return nil }
func (f *fakeNewChannel) ChannelType() string                            { return "session" }
func (f *fakeNewChannel) ExtraData() []byte                              { return nil }

func TestWaitForwardAddrAndExtraPayloadAndTerminalInfo(t *testing.T) {
	s := &TunnelServer{doneCh: make(chan struct{})}

	// 1. Timeout when no forward request or extra payload arrives.
	ch := make(chan cryptossh.NewChannel)
	reqs := make(chan *cryptossh.Request)
	_, _, err := s.waitForwardAddrAndExtraPayload(ch, reqs, 30*time.Millisecond)
	require.ErrorContains(t, err, "timeout")
	close(ch)
	close(reqs)

	// 2. Success when tcpip-forward request and exec channel payload arrive.
	s2 := &TunnelServer{doneCh: make(chan struct{})}
	defer close(s2.doneCh)
	ch2 := make(chan cryptossh.NewChannel, 1)
	reqs2 := make(chan *cryptossh.Request, 1)

	execReqs := make(chan *cryptossh.Request, 2)
	execReqs <- &cryptossh.Request{Type: "env", WantReply: false}
	execReqs <- &cryptossh.Request{
		Type:      "exec",
		WantReply: false,
		Payload:   cryptossh.Marshal(&execPayload{Command: "tcp -r 7000"}),
	}
	close(execReqs)

	ch2 <- &fakeNewChannel{ch: &trackingChannel{}, reqs: execReqs}
	reqs2 <- &cryptossh.Request{
		Type:      RequestTypeForward,
		WantReply: false,
		Payload:   cryptossh.Marshal(&tcpipForward{Host: "127.0.0.1", Port: 8080}),
	}

	gotAddr, gotExtra, err := s2.waitForwardAddrAndExtraPayload(ch2, reqs2, time.Second)
	require.NoError(t, err)
	require.Equal(t, &tcpipForward{Host: "127.0.0.1", Port: 8080}, gotAddr)
	require.Equal(t, "tcp -r 7000", gotExtra)

	// 3. Verify createSuccessInfo formatting.
	pc := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "demo-tcp",
			Type: "tcp",
		},
	}
	info := createSuccessInfo("alice", pc, &proxy.WorkingStatus{
		Name:       "demo-tcp",
		Type:       "tcp",
		RemoteAddr: ":6000",
	})
	require.Contains(t, info, "User: alice")
	require.Contains(t, info, "ProxyName: demo-tcp")
	require.Contains(t, info, "Type: tcp")
	require.Contains(t, info, "RemoteAddress: :6000")
}

func dialTestSSHClient(t *testing.T, addr string) (*cryptossh.Client, error) {
	t.Helper()
	return cryptossh.Dial("tcp", addr, &cryptossh.ClientConfig{
		User:            "v0",
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(), //nolint:gosec // test-only local SSH client
		Timeout:         2 * time.Second,
	})
}

func TestGatewayAndTunnelServerEndToEnd(t *testing.T) {
	peerLn := netpkg.NewInternalListener()
	gw, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1", peerLn)
	require.NoError(t, err)
	go gw.Run()
	t.Cleanup(func() {
		_ = gw.Close()
		_ = peerLn.Close()
	})

	addr := gw.ln.Addr().String()

	t.Run("help command returns usage over ssh channel", func(t *testing.T) {
		client, err := dialTestSSHClient(t, addr)
		require.NoError(t, err)
		defer client.Close()

		ok, _, err := client.SendRequest(RequestTypeForward, true, cryptossh.Marshal(&tcpipForward{
			Host: "127.0.0.1",
			Port: 8080,
		}))
		require.NoError(t, err)
		require.True(t, ok)

		ch, reqs, err := client.OpenChannel("session", nil)
		require.NoError(t, err)
		defer ch.Close()
		go cryptossh.DiscardRequests(reqs)

		ok, err = ch.SendRequest("exec", true, cryptossh.Marshal(&execPayload{Command: "tcp --help"}))
		require.NoError(t, err)
		require.True(t, ok)

		buf := make([]byte, 4096)
		n, err := ch.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "Usage:")
	})

	t.Run("invalid command writes error to ssh channel", func(t *testing.T) {
		client, err := dialTestSSHClient(t, addr)
		require.NoError(t, err)
		defer client.Close()

		ok, _, err := client.SendRequest(RequestTypeForward, true, cryptossh.Marshal(&tcpipForward{
			Host: "127.0.0.1",
			Port: 8080,
		}))
		require.NoError(t, err)
		require.True(t, ok)

		ch, reqs, err := client.OpenChannel("session", nil)
		require.NoError(t, err)
		defer ch.Close()
		go cryptossh.DiscardRequests(reqs)

		_, err = ch.SendRequest("exec", true, cryptossh.Marshal(&execPayload{Command: "udp --remote_port 6000"}))
		require.NoError(t, err)

		buf := make([]byte, 1024)
		n, err := ch.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "invalid proxy type")
	})

	t.Run("virtual client run and waitProxyStatusReady when peer listener closes", func(t *testing.T) {
		// Close peerLn so PutConn fails and virtual client exits cleanly
		_ = peerLn.Close()

		client, err := dialTestSSHClient(t, addr)
		require.NoError(t, err)
		defer client.Close()

		// Register handler for forwarded-tcpip channel so openConn can also be tested
		forwardedChs := client.HandleChannelOpen(ChannelTypeServerOpenChannel)
		go func() {
			for newCh := range forwardedChs {
				c, r, err := newCh.Accept()
				if err == nil {
					go cryptossh.DiscardRequests(r)
					_ = c.Close()
				}
			}
		}()

		ok, _, err := client.SendRequest(RequestTypeForward, true, cryptossh.Marshal(&tcpipForward{
			Host: "127.0.0.1",
			Port: 8080,
		}))
		require.NoError(t, err)
		require.True(t, ok)

		ch, reqs, err := client.OpenChannel("session", nil)
		require.NoError(t, err)
		defer ch.Close()
		go cryptossh.DiscardRequests(reqs)

		_, err = ch.SendRequest("exec", true, cryptossh.Marshal(&execPayload{Command: "tcp --remote_port 6000"}))
		require.NoError(t, err)

		buf := make([]byte, 1024)
		n, _ := ch.Read(buf)
		require.NotEmpty(t, string(buf[:n]))
	})

	t.Run("openConn opens forwarded-tcpip channel to client", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		privBytes, err := transport.NewRandomPrivateKey()
		require.NoError(t, err)
		signer, err := cryptossh.ParsePrivateKey(privBytes)
		require.NoError(t, err)
		sc := &cryptossh.ServerConfig{NoClientAuth: true}
		sc.AddHostKey(signer)

		serverDone := make(chan *TunnelServer, 1)
		go func() {
			c1, err := ln.Accept()
			if err != nil {
				return
			}
			srvConn, chs, reqs, err := cryptossh.NewServerConn(c1, sc)
			if err != nil {
				_ = c1.Close()
				return
			}
			go cryptossh.DiscardRequests(reqs)
			go func() {
				for newCh := range chs {
					_ = newCh.Reject(cryptossh.UnknownChannelType, "unused")
				}
			}()
			serverDone <- &TunnelServer{
				underlyingConn: c1,
				sshConn:        srvConn,
				doneCh:         make(chan struct{}),
			}
		}()

		c2, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer c2.Close()
		clientConn, chs, reqs, err := cryptossh.NewClientConn(c2, ln.Addr().String(), &cryptossh.ClientConfig{
			User:            "v0",
			HostKeyCallback: cryptossh.FixedHostKey(signer.PublicKey()),
		})
		require.NoError(t, err)
		defer clientConn.Close()
		go cryptossh.DiscardRequests(reqs)

		go func() {
			for newCh := range chs {
				if newCh.ChannelType() == ChannelTypeServerOpenChannel {
					ch, r, err := newCh.Accept()
					if err == nil {
						go cryptossh.DiscardRequests(r)
						_, _ = ch.Write([]byte("hello-from-ssh-client"))
						_ = ch.Close()
					}
				}
			}
		}()

		ts := <-serverDone
		defer ts.sshConn.Close()
		conn, err := ts.openConn(&tcpipForward{Host: "127.0.0.1", Port: 9000})
		require.NoError(t, err)
		defer conn.Close()

		data, err := io.ReadAll(conn)
		require.NoError(t, err)
		require.Equal(t, "hello-from-ssh-client", string(data))
	})
}
