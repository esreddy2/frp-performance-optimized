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

package nathole

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/util"
)

func TestClassifyNATFeatureAndCounts(t *testing.T) {
	_, err := ClassifyNATFeature(nil, nil)
	require.ErrorContains(t, err, "not enough addresses")
	_, err = ClassifyNATFeature([]string{"198.51.100.1:4000"}, nil)
	require.ErrorContains(t, err, "not enough addresses")
	_, err = ClassifyNATFeature([]string{"invalid-addr", "198.51.100.1:4000"}, nil)
	require.Error(t, err)
	_, err = ClassifyNATFeature([]string{"198.51.100.1:notaport", "198.51.100.1:4000"}, nil)
	require.Error(t, err)

	easyPublic, err := ClassifyNATFeature(
		[]string{"198.51.100.10:5000", "198.51.100.10:5000"},
		[]string{"198.51.100.10"},
	)
	require.NoError(t, err)
	require.Equal(t, EasyNAT, easyPublic.NatType)
	require.Equal(t, BehaviorNoChange, easyPublic.Behavior)
	require.True(t, easyPublic.PublicNetwork)
	require.False(t, easyPublic.RegularPortsChange)

	hardRegular, err := ClassifyNATFeature(
		[]string{"198.51.100.10:5000", "198.51.100.10:5003"},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, HardNAT, hardRegular.NatType)
	require.Equal(t, BehaviorPortChanged, hardRegular.Behavior)
	require.Equal(t, 3, hardRegular.PortsDifference)
	require.True(t, hardRegular.RegularPortsChange)
	require.False(t, hardRegular.PublicNetwork)

	hardIrregular, err := ClassifyNATFeature(
		[]string{"198.51.100.10:5000", "198.51.100.10:5020"},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, HardNAT, hardIrregular.NatType)
	require.Equal(t, BehaviorPortChanged, hardIrregular.Behavior)
	require.Equal(t, 20, hardIrregular.PortsDifference)
	require.False(t, hardIrregular.RegularPortsChange)

	hardIPChanged, err := ClassifyNATFeature(
		[]string{"198.51.100.10:5000", "198.51.100.11:5000"},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, HardNAT, hardIPChanged.NatType)
	require.Equal(t, BehaviorIPChanged, hardIPChanged.Behavior)

	hardBothChanged, err := ClassifyNATFeature(
		[]string{"198.51.100.10:5000", "198.51.100.11:5005"},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, HardNAT, hardBothChanged.NatType)
	require.Equal(t, BehaviorBothChanged, hardBothChanged.Behavior)

	easyCount, hardCount, regularCount := ClassifyFeatureCount([]*NatFeature{
		easyPublic,
		hardRegular,
		hardIrregular,
		hardIPChanged,
		hardBothChanged,
	})
	require.Equal(t, 1, easyCount)
	require.Equal(t, 4, hardCount)
	require.Equal(t, 1, regularCount)
}

func TestNatHoleMessageCodecAndLocalIPHelpers(t *testing.T) {
	key := []byte("secret-hole-key")
	orig := &msg.NatHoleSid{
		TransactionID: "tx-123",
		Sid:           "sid-456",
		Response:      true,
		Nonce:         "nonce-789",
	}
	encoded, err := EncodeMessage(orig, key)
	require.NoError(t, err)

	var decoded msg.NatHoleSid
	require.NoError(t, DecodeMessageInto(encoded, key, &decoded))
	require.Equal(t, *orig, decoded)

	// Decoding with wrong key must fail.
	var badDecoded msg.NatHoleSid
	require.Error(t, DecodeMessageInto(encoded, []byte("wrong-key"), &badDecoded))

	_, err = ListLocalIPsForNatHole(0)
	require.ErrorContains(t, err, "maxItems must be greater than 0")
	_, err = ListLocalIPsForNatHole(-1)
	require.ErrorContains(t, err, "maxItems must be greater than 0")

	ips, err := ListLocalIPsForNatHole(5)
	require.NoError(t, err)
	require.LessOrEqual(t, len(ips), 5)
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		require.NotNil(t, ip)
		require.NotNil(t, ip.To4(), "ListLocalIPsForNatHole must only return IPv4 addresses")
		require.False(t, ip.IsLoopback(), "ListLocalIPsForNatHole must exclude loopback addresses")
	}
}

type funcSender struct {
	sendFn func(msg.Message) error
}

func (f funcSender) Send(m msg.Message) error {
	return f.sendFn(m)
}

func TestPreCheckAndExchangeInfo(t *testing.T) {
	t.Run("PreCheck succeeds on empty error response and fails on server error", func(t *testing.T) {
		var tr transport.MessageTransporter
		tr = transport.NewMessageTransporter(funcSender{
			sendFn: func(m msg.Message) error {
				v, ok := m.(*msg.NatHoleVisitor)
				require.True(t, ok)
				require.True(t, v.PreCheck)
				errStr := ""
				if v.ProxyName == "denied-proxy" {
					errStr = "xtcp visitor user not allowed"
				}
				go tr.Dispatch(&msg.NatHoleResp{
					TransactionID: v.TransactionID,
					Error:         errStr,
				}, v.TransactionID)
				return nil
			},
		})

		require.NoError(t, PreCheck(t.Context(), tr, "allowed-proxy", time.Second))
		require.ErrorContains(t, PreCheck(t.Context(), tr, "denied-proxy", time.Second), "not allowed")
	})

	t.Run("ExchangeInfo validates response error and candidate addresses", func(t *testing.T) {
		var tr transport.MessageTransporter
		tr = transport.NewMessageTransporter(funcSender{
			sendFn: func(m msg.Message) error {
				c, ok := m.(*msg.NatHoleClient)
				require.True(t, ok)
				switch c.ProxyName {
				case "ok":
					go tr.Dispatch(&msg.NatHoleResp{
						TransactionID:  c.TransactionID,
						Sid:            c.Sid,
						CandidateAddrs: []string{"198.51.100.1:5000"},
					}, c.TransactionID)
				case "empty-candidates":
					go tr.Dispatch(&msg.NatHoleResp{
						TransactionID: c.TransactionID,
						Sid:           c.Sid,
					}, c.TransactionID)
				case "server-err":
					go tr.Dispatch(&msg.NatHoleResp{
						TransactionID: c.TransactionID,
						Error:         "analysis failed",
					}, c.TransactionID)
				}
				return nil
			},
		})

		resp, err := ExchangeInfo(t.Context(), tr, "tx-ok", &msg.NatHoleClient{
			TransactionID: "tx-ok",
			ProxyName:     "ok",
			Sid:           "s1",
		}, time.Second)
		require.NoError(t, err)
		require.Equal(t, []string{"198.51.100.1:5000"}, resp.CandidateAddrs)

		_, err = ExchangeInfo(t.Context(), tr, "tx-empty", &msg.NatHoleClient{
			TransactionID: "tx-empty",
			ProxyName:     "empty-candidates",
			Sid:           "s1",
		}, time.Second)
		require.ErrorContains(t, err, "empty candidate addresses")

		_, err = ExchangeInfo(t.Context(), tr, "tx-err", &msg.NatHoleClient{
			TransactionID: "tx-err",
			ProxyName:     "server-err",
			Sid:           "s1",
		}, time.Second)
		require.ErrorContains(t, err, "analysis failed")
	})
}

func TestControllerPreCheckAndAuthValidation(t *testing.T) {
	ctl, err := NewController(time.Hour)
	require.NoError(t, err)
	defer ctl.Close()

	sidCh, err := ctl.ListenClient("ssh-xtcp", "secret-key", []string{"alice"})
	require.NoError(t, err)
	require.NotNil(t, sidCh)

	// Duplicate ListenClient for the same proxy name must return an error.
	_, err = ctl.ListenClient("ssh-xtcp", "secret-key", []string{"alice"})
	require.ErrorContains(t, err, "is repeated")

	collectSingleResp := func(fn func(transport.MessageTransporter)) *msg.NatHoleResp {
		respCh := make(chan *msg.NatHoleResp, 1)
		tr := transport.NewMessageTransporter(funcSender{
			sendFn: func(m msg.Message) error {
				respCh <- m.(*msg.NatHoleResp)
				return nil
			},
		})
		fn(tr)
		select {
		case r := <-respCh:
			return r
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for NatHoleResp")
			return nil
		}
	}

	// PreCheck for unknown proxy.
	resp := collectSingleResp(func(tr transport.MessageTransporter) {
		ctl.HandleVisitor(&msg.NatHoleVisitor{
			TransactionID: "tx-1",
			ProxyName:     "missing",
			PreCheck:      true,
		}, tr, "alice")
	})
	require.Contains(t, resp.Error, "doesn't exist")

	// PreCheck for unauthorized user.
	resp = collectSingleResp(func(tr transport.MessageTransporter) {
		ctl.HandleVisitor(&msg.NatHoleVisitor{
			TransactionID: "tx-2",
			ProxyName:     "ssh-xtcp",
			PreCheck:      true,
		}, tr, "mallory")
	})
	require.Contains(t, resp.Error, "not allowed")

	// PreCheck for allowed user.
	resp = collectSingleResp(func(tr transport.MessageTransporter) {
		ctl.HandleVisitor(&msg.NatHoleVisitor{
			TransactionID: "tx-3",
			ProxyName:     "ssh-xtcp",
			PreCheck:      true,
		}, tr, "alice")
	})
	require.Empty(t, resp.Error)

	// Non-precheck with wrong SignKey returns auth failed.
	resp = collectSingleResp(func(tr transport.MessageTransporter) {
		ctl.HandleVisitor(&msg.NatHoleVisitor{
			TransactionID: "tx-4",
			ProxyName:     "ssh-xtcp",
			SignKey:       util.GetAuthKey("wrong-secret", time.Now().Unix()),
			Timestamp:     time.Now().Unix(),
		}, tr, "alice")
	})
	require.Contains(t, resp.Error, "auth failed")

	// CloseClient removes the proxy registration.
	ctl.CloseClient("ssh-xtcp")
	resp = collectSingleResp(func(tr transport.MessageTransporter) {
		ctl.HandleVisitor(&msg.NatHoleVisitor{
			TransactionID: "tx-5",
			ProxyName:     "ssh-xtcp",
			PreCheck:      true,
		}, tr, "alice")
	})
	require.Contains(t, resp.Error, "doesn't exist")
}

func TestControllerAnalysisAndGetRangePorts(t *testing.T) {
	require.Nil(t, getRangePorts([]string{"198.51.100.1:1000"}, 2, 0))
	require.Nil(t, getRangePorts(nil, 2, 10))
	require.Nil(t, getRangePorts([]string{"invalid"}, 2, 10))

	ports := getRangePorts([]string{"198.51.100.1:3"}, 5, 100)
	require.Equal(t, []msg.PortsRange{{From: 1, To: 13}}, ports)

	highPorts := getRangePorts([]string{"198.51.100.1:65533"}, 5, 100)
	require.Equal(t, []msg.PortsRange{{From: 65523, To: 65535}}, highPorts)

	ctl, err := NewController(time.Hour)
	require.NoError(t, err)
	session := &Session{
		sid: "sid-analysis",
		visitorMsg: &msg.NatHoleVisitor{
			TransactionID: "v-tx",
			Protocol:      "quic",
			MappedAddrs:   []string{"198.51.100.10:40000", "198.51.100.10:40000"},
			AssistedAddrs: []string{"10.0.0.2:40000"},
		},
		clientMsg: &msg.NatHoleClient{
			TransactionID: "c-tx",
			Sid:           "sid-analysis",
			MappedAddrs:   []string{"203.0.113.20:50000", "203.0.113.20:50002"},
			AssistedAddrs: []string{"10.0.0.3:50000"},
		},
	}

	vResp, cResp, err := ctl.analysis(session)
	require.NoError(t, err)
	require.Equal(t, "v-tx", vResp.TransactionID)
	require.Equal(t, "c-tx", cResp.TransactionID)
	require.Equal(t, "quic", vResp.Protocol)
	require.Equal(t, []string{"203.0.113.20:50000", "203.0.113.20:50002"}, vResp.CandidateAddrs)
	require.Equal(t, []string{"198.51.100.10:40000"}, cResp.CandidateAddrs)
	require.NotEmpty(t, session.analysisKey)

	// Reporting success for active session updates analyzer records.
	ctl.mu.Lock()
	ctl.sessions[session.sid] = session
	ctl.mu.Unlock()
	ctl.HandleReport(&msg.NatHoleReport{Sid: session.sid, Success: true})
}

func TestMakeHoleOverLoopbackUDP(t *testing.T) {
	receiverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer receiverConn.Close()

	senderConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer senderConn.Close()

	sid := "hole-sid-001"
	key := []byte("shared-hole-secret")

	receiverResp := &msg.NatHoleResp{
		TransactionID:  "rx-tx",
		Sid:            sid,
		CandidateAddrs: []string{senderConn.LocalAddr().String()},
		DetectBehavior: msg.NatHoleDetectBehavior{
			Mode:          DetectMode0,
			Role:          DetectRoleReceiver,
			ReadTimeoutMs: 2000,
		},
	}
	senderResp := &msg.NatHoleResp{
		TransactionID:  "tx-tx",
		Sid:            sid,
		CandidateAddrs: []string{receiverConn.LocalAddr().String()},
		DetectBehavior: msg.NatHoleDetectBehavior{
			Mode:          DetectMode0,
			Role:          DetectRoleSender,
			SendDelayMs:   20,
			ReadTimeoutMs: 2000,
		},
	}

	type holeResult struct {
		conn  *net.UDPConn
		raddr *net.UDPAddr
		err   error
	}
	rxCh := make(chan holeResult, 1)
	txCh := make(chan holeResult, 1)

	var wg sync.WaitGroup
	wg.Go(func() {
		c, raddr, hErr := MakeHole(context.Background(), receiverConn, receiverResp, key)
		rxCh <- holeResult{conn: c, raddr: raddr, err: hErr}
	})
	wg.Go(func() {
		c, raddr, hErr := MakeHole(context.Background(), senderConn, senderResp, key)
		txCh <- holeResult{conn: c, raddr: raddr, err: hErr}
	})
	wg.Wait()

	rxRes := <-rxCh
	txRes := <-txCh
	require.NoError(t, rxRes.err)
	require.NoError(t, txRes.err)
	require.Same(t, receiverConn, rxRes.conn)
	require.Same(t, senderConn, txRes.conn)
	require.Equal(t, senderConn.LocalAddr().String(), rxRes.raddr.String())
	require.Equal(t, receiverConn.LocalAddr().String(), txRes.raddr.String())
}

func TestControllerHandleVisitorSidChTimeout(t *testing.T) {
	origTimeout := sendSidTimeout
	sendSidTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sendSidTimeout = origTimeout })

	ctl, err := NewController(time.Hour)
	require.NoError(t, err)
	defer ctl.Close()

	_, err = ctl.ListenClient("timeout-proxy", "valid-sk", []string{"user1"})
	require.NoError(t, err)

	respCh := make(chan *msg.NatHoleResp, 1)
	tr := transport.NewMessageTransporter(funcSender{
		sendFn: func(m msg.Message) error {
			respCh <- m.(*msg.NatHoleResp)
			return nil
		},
	})

	now := time.Now().Unix()
	ctl.HandleVisitor(&msg.NatHoleVisitor{
		TransactionID: "tx-timeout",
		ProxyName:     "timeout-proxy",
		SignKey:       util.GetAuthKey("valid-sk", now),
		Timestamp:     now,
	}, tr, "user1")

	select {
	case resp := <-respCh:
		require.Contains(t, resp.Error, "send sid to client failed")
	case <-time.After(time.Second):
		t.Fatal("HandleVisitor did not return within timeout")
	}

	ctl.mu.RLock()
	require.Empty(t, ctl.sessions)
	ctl.mu.RUnlock()
}
