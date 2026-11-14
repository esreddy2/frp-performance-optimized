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

package v1

import (
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
)

func TestClientConfigComplete(t *testing.T) {
	require := require.New(t)
	c := &ClientConfig{}
	err := c.Complete()
	require.NoError(err)

	require.EqualValues("token", c.Auth.Method)
	require.Equal(true, lo.FromPtr(c.Transport.TCPMux))
	require.Equal("v1", c.Transport.WireProtocol)
	require.Equal(true, lo.FromPtr(c.LoginFailExit))
	require.Equal(true, lo.FromPtr(c.Transport.TLS.Enable))
	require.Equal(true, lo.FromPtr(c.Transport.TLS.DisableCustomTLSFirstByte))
	require.NotEmpty(c.NatHoleSTUNServer)
}

func TestAuthClientConfig_Complete(t *testing.T) {
	require := require.New(t)
	cfg := &AuthClientConfig{}
	err := cfg.Complete()
	require.NoError(err)
	require.EqualValues("token", cfg.Method)
}

func TestClientTransportConfig_HTTPProxyFallback(t *testing.T) {
	require := require.New(t)

	// When only HTTP_PROXY (uppercase) is set
	t.Setenv("http_proxy", "")
	t.Setenv("HTTP_PROXY", "http://uppercase-proxy:8080")
	c := &ClientTransportConfig{}
	c.Complete()
	require.Equal("http://uppercase-proxy:8080", c.ProxyURL)

	// When lowercase http_proxy is set, it takes precedence
	t.Setenv("http_proxy", "http://lowercase-proxy:8080")
	c2 := &ClientTransportConfig{}
	c2.Complete()
	require.Equal("http://lowercase-proxy:8080", c2.ProxyURL)
}
