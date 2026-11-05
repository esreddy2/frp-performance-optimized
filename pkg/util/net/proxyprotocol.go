// Copyright 2025 The frp Authors
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

package net

import (
	"bytes"
	"fmt"
	"net"

	pp "github.com/pires/go-proxyproto"
)

func BuildProxyProtocolHeaderStruct(srcAddr, dstAddr net.Addr, version string) *pp.Header {
	var versionByte byte
	switch version {
	case "v1":
		versionByte = 1
	case "v2", "":
		versionByte = 2 // default to v2
	default:
		return nil
	}
	h := pp.HeaderProxyFromAddrs(versionByte, srcAddr, dstAddr)
	// Reject no-op headers produced for nil or unsupported/mismatched
	// addresses so callers can distinguish a real proxy header.
	if h == nil || h.Command != pp.PROXY {
		return nil
	}
	return h
}

func BuildProxyProtocolHeader(srcAddr, dstAddr net.Addr, version string) ([]byte, error) {
	h := BuildProxyProtocolHeaderStruct(srcAddr, dstAddr, version)
	if h == nil {
		return nil, fmt.Errorf("invalid proxy protocol version or addresses: version=%q", version)
	}

	// Convert header to bytes using a buffer
	var buf bytes.Buffer
	_, err := h.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write proxy protocol header: %v", err)
	}
	return buf.Bytes(), nil
}
