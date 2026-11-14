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

//go:build darwin

package vnet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDarwinGeneratePeerIP verifies CANON-060:
// 1. Regular IPv4 increments the last octet.
// 2. IPv4 address ending with 255 decrements to 254 rather than overflowing uint8 to 0.
// 3. IPv6 peer IP generation increments without corruption.
func TestDarwinGeneratePeerIP(t *testing.T) {
	require := require.New(t)

	// Regular IPv4
	ip1 := net.ParseIP("192.168.1.1")
	peer1 := generatePeerIP(ip1)
	require.Equal("192.168.1.2", peer1.String())

	// Boundary IPv4 ending in .255 -> should become .254, NOT .0
	ip255 := net.ParseIP("192.168.1.255")
	peer255 := generatePeerIP(ip255)
	require.Equal("192.168.1.254", peer255.String())

	// IPv6 address
	ipV6 := net.ParseIP("fd00::1")
	peerV6 := generatePeerIP(ipV6)
	require.Equal("fd00::2", peerV6.String())

	// IPv6 address with byte overflow
	ipV6Overflow := net.ParseIP("fd00::ff")
	peerV6Overflow := generatePeerIP(ipV6Overflow)
	require.Equal("fd00::100", peerV6Overflow.String())
}
