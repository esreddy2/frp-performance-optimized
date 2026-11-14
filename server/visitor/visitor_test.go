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

package visitor

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/util/util"
)

func TestManagerNewConnCarriesWireProtocolAndUDPPacketCodec(t *testing.T) {
	vm := NewManager()
	listener, err := vm.Listen("sudp", "secret", []string{"*"})
	require.NoError(t, err)
	defer listener.Close()

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	now := time.Now().Unix()
	errCh := make(chan error, 1)
	go func() {
		errCh <- vm.NewConn(
			"sudp",
			server,
			now,
			util.GetAuthKey("secret", now),
			false,
			false,
			"user",
			wire.ProtocolV2,
			wire.UDPPacketCodecBinary,
		)
	}()

	acceptedConn, err := listener.Accept()
	require.NoError(t, err)
	defer acceptedConn.Close()

	metadata, ok := acceptedConn.(interface {
		WireProtocol() string
		UDPPacketCodec() string
	})
	require.True(t, ok)
	require.Equal(t, wire.ProtocolV2, metadata.WireProtocol())
	require.Equal(t, wire.UDPPacketCodecBinary, metadata.UDPPacketCodec())
	require.NoError(t, <-errCh)
}

func TestManagerAuthAllowUsersEncryptionCompressionAndLifecycle(t *testing.T) {
	require := require.New(t)
	vm := NewManager()

	ln, err := vm.Listen("stcp-svc", "secret-key", []string{"alice", "bob"})
	require.NoError(err)

	// Duplicate Listen on same name is rejected
	_, err = vm.Listen("stcp-svc", "secret-key", []string{"*"})
	require.ErrorContains(err, "is repeated")

	now := time.Now().Unix()
	validSign := util.GetAuthKey("secret-key", now)

	// Non-existent listener
	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	err = vm.NewConn("unknown-svc", s1, now, validSign, false, false, "alice", wire.ProtocolV1)
	require.ErrorContains(err, "doesn't exist")

	// Invalid auth signature
	err = vm.NewConn("stcp-svc", s1, now, "bad-signature", false, false, "alice", wire.ProtocolV1)
	require.ErrorContains(err, "auth failed")

	// Unauthorized user (when allowUsers does not contain "*")
	err = vm.NewConn("stcp-svc", s1, now, validSign, false, false, "mallory", wire.ProtocolV1)
	require.ErrorContains(err, "not allowed")

	// Authorized user with both encryption and compression enabled
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- vm.NewConn("stcp-svc", serverRaw, now, validSign, true, true, "bob", wire.ProtocolV1)
	}()

	accepted, err := ln.Accept()
	require.NoError(err)
	require.NoError(<-errCh)
	defer accepted.Close()

	// CloseListener removes only that listener and unblocks Accept
	vm.CloseListener("stcp-svc")
	_, err = ln.Accept()
	require.Error(err)

	// After CloseListener, a new listener with the same name can be registered
	ln2, err := vm.Listen("stcp-svc", "secret-key-2", []string{"*"})
	require.NoError(err)

	// Close shuts down all remaining listeners
	require.NoError(vm.Close())
	_, err = ln2.Accept()
	require.Error(err)
}

func TestManagerTimestampFreshness(t *testing.T) {
	require := require.New(t)
	vm := NewManager()

	ln, err := vm.Listen("fresh-svc", "secret", []string{"*"})
	require.NoError(err)
	defer ln.Close()

	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()

	// Timestamp 120 seconds in the past
	oldTime := time.Now().Unix() - 120
	oldSign := util.GetAuthKey("secret", oldTime)
	err = vm.NewConn("fresh-svc", s1, oldTime, oldSign, false, false, "alice", wire.ProtocolV1)
	require.ErrorContains(err, "timestamp expired")

	// Timestamp 120 seconds in the future
	futureTime := time.Now().Unix() + 120
	futureSign := util.GetAuthKey("secret", futureTime)
	err = vm.NewConn("fresh-svc", s1, futureTime, futureSign, false, false, "alice", wire.ProtocolV1)
	require.ErrorContains(err, "timestamp expired")
}
