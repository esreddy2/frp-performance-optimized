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

package client

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
)

func newCGTestControl(t *testing.T, common *v1.ClientCommonConfig) (*Control, *trackingConn, *testConnector) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	tracked := &trackingConn{Conn: clientConn}
	connector := &testConnector{conn: tracked}

	authRuntime, err := auth.BuildClientAuth(&v1.AuthClientConfig{
		Method: v1.AuthMethodToken,
		Token:  "token",
	})
	require.NoError(t, err)

	if common == nil {
		common = &v1.ClientCommonConfig{}
	}

	ctl, err := NewControl(context.Background(), &SessionContext{
		Common:    common,
		RunID:     "cg-test-run",
		Conn:      msg.NewConn(tracked, msg.NewV1ReadWriter(tracked)),
		Auth:      authRuntime,
		Connector: newMessageConnector(connector, ""),
	})
	require.NoError(t, err)
	return ctl, tracked, connector
}

// CG-008: heartbeat timeout closes the session.
func TestControlHeartbeatTimeoutClosesSessionCG008(t *testing.T) {
	common := &v1.ClientCommonConfig{
		Transport: v1.ClientTransportConfig{
			HeartbeatInterval: 1,
			HeartbeatTimeout:  1,
		},
	}
	ctl, tracked, connector := newCGTestControl(t, common)
	t.Cleanup(func() { _ = ctl.GracefulClose(0) })

	ctl.lastPong.Store(time.Now().Add(-10 * time.Second))
	ctl.heartbeatWorker()

	require.Eventually(t, func() bool {
		return tracked.closed.Load() || connector.closed.Load()
	}, 3*time.Second, 10*time.Millisecond)
}

// CG-009: Pong error path closes the session.
func TestControlPongErrorClosesSessionCG009(t *testing.T) {
	ctl, tracked, connector := newCGTestControl(t, nil)
	t.Cleanup(func() { _ = ctl.GracefulClose(0) })

	ctl.handlePong(&msg.Pong{Error: "pong failed"})

	require.True(t, tracked.closed.Load() || connector.closed.Load())
}

// CG-013: repeated/concurrent closeSession is idempotent.
func TestControlCloseSessionIdempotentCG013(t *testing.T) {
	ctl, tracked, connector := newCGTestControl(t, nil)
	t.Cleanup(func() { _ = ctl.GracefulClose(0) })

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			ctl.closeSession()
		})
	}
	wg.Wait()
	ctl.closeSession()

	require.True(t, tracked.closed.Load() || connector.closed.Load())
}

// CG-011: direct Control-level GracefulClose.
func TestControlGracefulCloseCG011(t *testing.T) {
	ctl, _, _ := newCGTestControl(t, nil)

	start := time.Now()
	err := ctl.GracefulClose(50 * time.Millisecond)
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond)

	select {
	case <-ctl.Done():
	default:
		t.Fatal("doneCh was not closed")
	}

	// Idempotent: a second call returns immediately.
	err = ctl.GracefulClose(0)
	require.NoError(t, err)
}

// CG-010: worker cleanup closes doneCh (and stops managers).
func TestControlWorkerCleanupClosesDoneChCG010(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	tracked := &trackingConn{Conn: clientConn}
	connector := &testConnector{conn: tracked}

	authRuntime, err := auth.BuildClientAuth(&v1.AuthClientConfig{
		Method: v1.AuthMethodToken,
		Token:  "token",
	})
	require.NoError(t, err)

	common := &v1.ClientCommonConfig{}
	ctl, err := NewControl(context.Background(), &SessionContext{
		Common:    common,
		RunID:     "cg-worker-run",
		Conn:      msg.NewConn(tracked, msg.NewV1ReadWriter(tracked)),
		Auth:      authRuntime,
		Connector: newMessageConnector(connector, ""),
	})
	require.NoError(t, err)

	go ctl.worker()

	// Trigger dispatcher exit.
	_ = serverConn.Close()

	select {
	case <-ctl.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("doneCh was not closed by worker cleanup")
	}
}

// CG-012: V2 crypto negotiation failure cleanup in Dial.
func TestControlSessionDialerDialV2CryptoNegotiationFailureClosesResourcesCG012(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()

	clientConn := &trackingConn{Conn: clientRaw}
	connector := &testConnector{conn: clientConn}

	serverErrCh := make(chan error, 1)
	go func() {
		magic := make([]byte, len(wire.MagicV2))
		if _, err := io.ReadFull(serverRaw, magic); err != nil {
			serverErrCh <- err
			return
		}
		wireConn := wire.NewConn(serverRaw)
		clientHelloFrame, err := wireConn.ReadFrame()
		if err != nil {
			serverErrCh <- err
			return
		}
		var hello wire.ClientHello
		if err := wireConn.UnmarshalFrame(clientHelloFrame, &hello); err != nil {
			serverErrCh <- err
			return
		}
		if err := wire.ValidateClientHello(hello); err != nil {
			serverErrCh <- err
			return
		}

		rw := msg.NewV2ReadWriterWithConn(wireConn)
		var loginMsg msg.Login
		if err := rw.ReadMsgInto(&loginMsg); err != nil {
			serverErrCh <- err
			return
		}

		serverHello, _, err := wire.NewServerHello(hello)
		if err != nil {
			serverErrCh <- err
			return
		}
		// Force a missing key share to trigger the requireKeyShare failure path.
		serverHello.Selected.Crypto.ServerKeyShare = nil
		serverHelloFrame, err := wire.NewJSONFrame(wire.FrameTypeServerHello, serverHello)
		if err != nil {
			serverErrCh <- err
			return
		}
		if err := wireConn.WriteFrame(serverHelloFrame); err != nil {
			serverErrCh <- err
			return
		}
		if err := rw.WriteMsg(&msg.LoginResp{RunID: "run-v2-no-keyshare"}); err != nil {
			serverErrCh <- err
			return
		}
		_ = serverRaw.Close()
		serverErrCh <- nil
	}()

	dialer := newTestControlSessionDialer(t, wire.ProtocolV2, connector, nil)
	dialer.common.Transport.RequireKeyShare = true

	sessionCtx, err := dialer.Dial("")
	require.Error(t, err)
	require.Nil(t, sessionCtx)
	require.Contains(t, err.Error(), "requireKeyShare")
	require.True(t, clientConn.closed.Load())
	require.True(t, connector.closed.Load())

	select {
	case serr := <-serverErrCh:
		if serr != nil {
			t.Logf("server: %v", serr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not finish")
	}
}

func TestControlHeartbeatWorkerExitsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	common := &v1.ClientCommonConfig{
		Auth: v1.AuthClientConfig{
			Method: v1.AuthMethodToken,
			Token:  "token",
		},
		Transport: v1.ClientTransportConfig{
			HeartbeatInterval: 30,
			HeartbeatTimeout:  90,
		},
	}
	authRuntime, err := auth.BuildClientAuth(&common.Auth)
	require.NoError(t, err)

	ctl, err := NewControl(ctx, &SessionContext{
		Common:    common,
		RunID:     "hb-cancel-run",
		Conn:      msg.NewConn(clientConn, msg.NewV1ReadWriter(clientConn)),
		Auth:      authRuntime,
		Connector: newMessageConnector(&testConnector{}, ""),
	})
	require.NoError(t, err)

	// Start heartbeatWorker without calling worker() or GracefulClose().
	ctl.heartbeatWorker()

	// Canceling the parent ctx must terminate the heartbeat goroutines.
	cancel()

	done := make(chan struct{})
	go func() {
		ctl.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat goroutines did not exit when parent ctx was cancelled")
	}
}

func TestControlGracefulCloseRacesWithWorker(t *testing.T) {
	for range 20 {
		clientConn, serverConn := net.Pipe()
		common := &v1.ClientCommonConfig{
			Auth: v1.AuthClientConfig{
				Method: v1.AuthMethodToken,
				Token:  "token",
			},
			Transport: v1.ClientTransportConfig{
				HeartbeatInterval: 30,
				HeartbeatTimeout:  90,
			},
		}
		authRuntime, err := auth.BuildClientAuth(&common.Auth)
		require.NoError(t, err)

		ctl, err := NewControl(context.Background(), &SessionContext{
			Common:    common,
			RunID:     "race-worker-close",
			Conn:      msg.NewConn(clientConn, msg.NewV1ReadWriter(clientConn)),
			Auth:      authRuntime,
			Connector: newMessageConnector(&testConnector{}, ""),
		})
		require.NoError(t, err)

		go ctl.worker()
		_ = ctl.GracefulClose(0)
		_ = serverConn.Close()
	}
}
