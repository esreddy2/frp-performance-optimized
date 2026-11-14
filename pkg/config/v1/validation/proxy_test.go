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

package validation

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/naming"
)

func TestValidateDomainConfigForServerRejectsSubdomainHostCaseInsensitively(t *testing.T) {
	tests := []struct {
		name          string
		subDomainHost string
		customDomain  string
		wantErr       bool
	}{
		{
			name:          "lowercase subdomain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.frp.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case custom domain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.FRP.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case wildcard domain",
			subDomainHost: "frp.example.com",
			customDomain:  "*.FRP.example.com",
			wantErr:       true,
		},
		{
			name:          "mixed case subdomain host",
			subDomainHost: "FRP.Example.Com",
			customDomain:  "victim.frp.example.com",
			wantErr:       true,
		},
		{
			name:          "external domain",
			subDomainHost: "frp.example.com",
			customDomain:  "victim.example.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomainConfigForServer(
				&v1.DomainConfig{CustomDomains: []string{tt.customDomain}},
				&v1.ServerConfig{SubDomainHost: tt.subDomainHost},
			)
			if tt.wantErr {
				require.ErrorContains(t, err, "should not belong to subdomain host")
				return
			}
			require.NoError(t, err)
		})
	}
}

// The quic datagram lane identifies a proxy by its wire-level name, and the
// identifier field of a datagram frame holds a single length byte. The
// wire-level name is the proxy name with the user prefix, so the limit
// applies to the effective name on the wire, not to the local
// configuration name.
func TestValidateUDPProxyConfigForClientChecksTheWireLevelName(t *testing.T) {
	const user = "dg-user"

	tests := []struct {
		name          string
		user          string
		proxyName     string
		quicDatagrams bool
		wantErr       bool
	}{
		{
			name:          "the wire name fits",
			user:          user,
			proxyName:     strings.Repeat("n", naming.MaxDatagramIdentifierLength-len(user)-1),
			quicDatagrams: true,
		},
		{
			name:          "the wire name is one byte too long",
			user:          user,
			proxyName:     strings.Repeat("n", naming.MaxDatagramIdentifierLength-len(user)),
			quicDatagrams: true,
			wantErr:       true,
		},
		{
			name:          "the proxy name alone is too long",
			proxyName:     strings.Repeat("n", naming.MaxDatagramIdentifierLength+1),
			quicDatagrams: true,
			wantErr:       true,
		},
		{
			name:      "the lane is not requested, so the name does not matter",
			proxyName: strings.Repeat("n", naming.MaxDatagramIdentifierLength+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &v1.UDPProxyConfig{
				ProxyBaseConfig: v1.ProxyBaseConfig{
					Name: tt.proxyName,
					Type: string(v1.ProxyTypeUDP),
				},
				QUICDatagrams: tt.quicDatagrams,
			}
			err := validateUDPProxyConfigForClient(cfg, tt.user)
			if tt.wantErr {
				require.ErrorContains(t, err, "the quic datagram lane needs a wire-level proxy name")
				return
			}
			require.NoError(t, err)
		})
	}
}

// The client validation reports the rule for the whole proxy config, so the
// datagram rule is reachable through the exported entry point as well.
func TestValidateProxyConfigurerForClientChecksTheDatagramName(t *testing.T) {
	cfg := &v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: strings.Repeat("n", naming.MaxDatagramIdentifierLength+1),
			Type: string(v1.ProxyTypeUDP),
			Transport: v1.ProxyTransport{
				BandwidthLimitMode: types.BandwidthLimitModeClient,
			},
		},
		QUICDatagrams: true,
	}
	require.ErrorContains(t, ValidateProxyConfigurerForClient(cfg, ""),
		"the quic datagram lane needs a wire-level proxy name")

	// Without the datagram lane the name is not constrained.
	cfg.QUICDatagrams = false
	require.NoError(t, ValidateProxyConfigurerForClient(cfg, ""))
}

func TestValidateUDPProxyConfigQUICDatagramStrict(t *testing.T) {
	cfg := &v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "test-udp",
			Type: string(v1.ProxyTypeUDP),
			Transport: v1.ProxyTransport{
				BandwidthLimitMode: types.BandwidthLimitModeClient,
			},
		},
		QUICDatagrams:      false,
		QUICDatagramStrict: true,
	}
	require.ErrorContains(t, ValidateProxyConfigurerForClient(cfg, ""),
		"quicDatagramStrict requires quicDatagrams to be true")

	cfg.QUICDatagrams = true
	require.NoError(t, ValidateProxyConfigurerForClient(cfg, ""))
}

func TestValidateProxyTransportProxyProtocolMode(t *testing.T) {
	tests := []struct {
		name                 string
		proxyType            string
		proxyProtocolVersion string
		proxyProtocolMode    string
		wantErr              string
	}{
		{
			name:                 "valid default empty mode with version on tcp",
			proxyType:            "tcp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "",
		},
		{
			name:                 "valid default empty mode with version on udp",
			proxyType:            "udp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "",
		},
		{
			name:                 "valid first-packet mode on udp",
			proxyType:            "udp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "first-packet",
		},
		{
			name:                 "valid per-packet mode on udp",
			proxyType:            "udp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "per-packet",
		},
		{
			name:                 "valid per-packet mode on sudp",
			proxyType:            "sudp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "per-packet",
		},
		{
			name:                 "rejected non-empty mode on tcp",
			proxyType:            "tcp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "first-packet",
			wantErr:              "transport.proxyProtocolMode is only supported for udp and sudp proxies",
		},
		{
			name:                 "invalid mode",
			proxyType:            "udp",
			proxyProtocolVersion: "v2",
			proxyProtocolMode:    "every-packet",
			wantErr:              "not support proxy protocol mode",
		},
		{
			name:                 "per-packet mode without version",
			proxyType:            "udp",
			proxyProtocolVersion: "",
			proxyProtocolMode:    "per-packet",
			wantErr:              "transport.proxyProtocolMode requires transport.proxyProtocol to be set to v1 or v2",
		},
		{
			name:                 "first-packet mode without version",
			proxyType:            "udp",
			proxyProtocolVersion: "",
			proxyProtocolMode:    "first-packet",
			wantErr:              "transport.proxyProtocolMode requires transport.proxyProtocol to be set to v1 or v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &v1.ProxyBaseConfig{
				Name: "test-proxy",
				Type: tt.proxyType,
				ProxyBackend: v1.ProxyBackend{
					LocalPort: 80,
				},
				Transport: v1.ProxyTransport{
					BandwidthLimitMode:   types.BandwidthLimitModeClient,
					ProxyProtocolVersion: tt.proxyProtocolVersion,
					ProxyProtocolMode:    tt.proxyProtocolMode,
				},
			}
			err := validateProxyBaseConfigForClient(base)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateProxyTransportProxyProtocolAndSocketMark(t *testing.T) {
	tests := []struct {
		name          string
		proxyProtocol string
		socketMark    int
		wantErr       string
	}{
		{
			name:          "valid tproxy with zero mark",
			proxyProtocol: "tproxy",
			socketMark:    0,
		},
		{
			name:          "valid tproxy with positive mark",
			proxyProtocol: "tproxy",
			socketMark:    100,
		},
		{
			name:          "valid tproxy with max int32 mark",
			proxyProtocol: "tproxy",
			socketMark:    math.MaxInt32,
		},
		{
			name:          "valid v2 protocol",
			proxyProtocol: "v2",
			socketMark:    0,
		},
		{
			name:          "invalid protocol",
			proxyProtocol: "invalid",
			wantErr:       "not support proxy protocol",
		},
		{
			name:          "invalid negative socket mark",
			proxyProtocol: "tproxy",
			socketMark:    -1,
			wantErr:       "transport.socketMark should be greater than or equal to 0",
		},
	}

	if math.MaxInt > math.MaxInt32 {
		var overMaxInt32 int64 = math.MaxInt32 + 1
		tests = append(tests, struct {
			name          string
			proxyProtocol string
			socketMark    int
			wantErr       string
		}{
			name:          "invalid socket mark exceeding max int32",
			proxyProtocol: "tproxy",
			socketMark:    int(overMaxInt32),
			wantErr:       "transport.socketMark should be less than or equal to 2147483647",
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &v1.ProxyBaseConfig{
				Name: "test-proxy",
				Type: "tcp",
				ProxyBackend: v1.ProxyBackend{
					LocalPort: 80,
				},
				Transport: v1.ProxyTransport{
					BandwidthLimitMode: types.BandwidthLimitModeClient,
					ProxyProtocol:      tt.proxyProtocol,
					SocketMark:         tt.socketMark,
				},
			}
			err := validateProxyBaseConfigForClient(base)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestProxyBaseConfigCompleteSocketMarkDefaulting(t *testing.T) {
	// tproxy with no socketMark defaults to 1
	base1 := &v1.ProxyBaseConfig{
		Transport: v1.ProxyTransport{
			ProxyProtocol: "tproxy",
		},
	}
	base1.Complete()
	require.Equal(t, 1, base1.Transport.SocketMark)

	// tproxy with explicit socketMark retains it
	base2 := &v1.ProxyBaseConfig{
		Transport: v1.ProxyTransport{
			ProxyProtocol: "tproxy",
			SocketMark:    42,
		},
	}
	base2.Complete()
	require.Equal(t, 42, base2.Transport.SocketMark)

	// non-tproxy ignores/clears socketMark; non-UDP does not default ProxyProtocolMode
	base3 := &v1.ProxyBaseConfig{
		Type: "tcp",
		Transport: v1.ProxyTransport{
			ProxyProtocol: "v2",
			SocketMark:    42,
		},
	}
	base3.Complete()
	require.Equal(t, 0, base3.Transport.SocketMark)
	require.Equal(t, "", base3.Transport.ProxyProtocolMode)

	// udp and sudp default ProxyProtocolMode to first-packet when v1/v2 is set
	baseUDP := &v1.ProxyBaseConfig{
		Type: "udp",
		Transport: v1.ProxyTransport{
			ProxyProtocol: "v2",
			SocketMark:    42,
		},
	}
	baseUDP.Complete()
	require.Equal(t, 0, baseUDP.Transport.SocketMark)
	require.Equal(t, "first-packet", baseUDP.Transport.ProxyProtocolMode)

	baseSUDP := &v1.ProxyBaseConfig{
		Type: "sudp",
		Transport: v1.ProxyTransport{
			ProxyProtocol: "v1",
		},
	}
	baseSUDP.Complete()
	require.Equal(t, "first-packet", baseSUDP.Transport.ProxyProtocolMode)

	// proxyProtocolVersion alias is mapped to proxyProtocol and preserves mode for validation
	base4 := &v1.ProxyBaseConfig{
		Transport: v1.ProxyTransport{
			ProxyProtocolVersion: "tproxy",
			ProxyProtocolMode:    "per-packet",
		},
	}
	base4.Complete()
	require.Equal(t, "tproxy", base4.Transport.ProxyProtocol)
	require.Equal(t, 1, base4.Transport.SocketMark)
	require.Equal(t, "per-packet", base4.Transport.ProxyProtocolMode)

	// empty proxyProtocol clears socketMark while preserving mode for validation
	base5 := &v1.ProxyBaseConfig{
		Transport: v1.ProxyTransport{
			ProxyProtocolMode: "first-packet",
			SocketMark:        9,
		},
	}
	base5.Complete()
	require.Equal(t, "first-packet", base5.Transport.ProxyProtocolMode)
	require.Equal(t, 0, base5.Transport.SocketMark)
}

func TestProxyBaseConfigCompletePreservesProxyProtocolModeForValidation(t *testing.T) {
	tests := []struct {
		name              string
		proxyType         string
		proxyProtocol     string
		proxyProtocolMode string
		wantErr           string
	}{
		{
			name:              "tproxy with proxyProtocolMode on udp is rejected after Complete",
			proxyType:         "udp",
			proxyProtocol:     "tproxy",
			proxyProtocolMode: "per-packet",
			wantErr:           "transport.proxyProtocolMode requires transport.proxyProtocol to be set to v1 or v2",
		},
		{
			name:              "tproxy with proxyProtocolMode on tcp is rejected after Complete",
			proxyType:         "tcp",
			proxyProtocol:     "tproxy",
			proxyProtocolMode: "first-packet",
			wantErr:           "transport.proxyProtocolMode is only supported for udp and sudp proxies",
		},
		{
			name:              "empty proxyProtocol with proxyProtocolMode on udp is rejected after Complete",
			proxyType:         "udp",
			proxyProtocol:     "",
			proxyProtocolMode: "first-packet",
			wantErr:           "transport.proxyProtocolMode requires transport.proxyProtocol to be set to v1 or v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &v1.ProxyBaseConfig{
				Name: "test-proxy",
				Type: tt.proxyType,
				ProxyBackend: v1.ProxyBackend{
					LocalPort: 80,
				},
				Transport: v1.ProxyTransport{
					ProxyProtocol:     tt.proxyProtocol,
					ProxyProtocolMode: tt.proxyProtocolMode,
				},
			}
			base.Complete()
			err := validateProxyBaseConfigForClient(base)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidateAnnotationsQualifiedName(t *testing.T) {
	require.NoError(t, ValidateAnnotations(map[string]string{
		"frp.e2e.test/foo":       "value1",
		"app.kubernetes.io/name": "value2",
	}))
	// The call site lowercases keys before validation.
	require.NoError(t, ValidateAnnotations(map[string]string{"Example.COM/MyName": "value"}))

	err := ValidateAnnotations(map[string]string{"bad key": "value"})
	require.ErrorContains(t, err, "annotation key bad key is invalid: name part must consist of alphanumeric characters")

	err = ValidateAnnotations(map[string]string{"example.com/": "value"})
	require.ErrorContains(t, err, "name part must be non-empty")

	// Oversized annotations (> 256 KB) must be rejected
	err = ValidateAnnotations(map[string]string{"valid.key": strings.Repeat("a", TotalAnnotationSizeLimitB+1)})
	require.ErrorContains(t, err, "annotations size")
}

type fakeProxyConfigurer struct {
	v1.ProxyBaseConfig
}

func (f *fakeProxyConfigurer) Clone() v1.ProxyConfigurer { return f }

type fakeVisitorConfigurer struct {
	v1.VisitorBaseConfig
}

func (f *fakeVisitorConfigurer) Clone() v1.VisitorConfigurer { return f }

func TestValidateAllProxyPluginsVisitorsAndServerRules(t *testing.T) {
	require := require.New(t)

	// 1. ValidateClientPluginOptions for all plugin types
	require.ErrorContains(ValidateClientPluginOptions(&v1.HTTP2HTTPSPluginOptions{}), "localAddr is required")
	require.NoError(ValidateClientPluginOptions(&v1.HTTP2HTTPSPluginOptions{LocalAddr: "127.0.0.1:80"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.HTTP2HTTPPluginOptions{}), "localAddr is required")
	require.NoError(ValidateClientPluginOptions(&v1.HTTP2HTTPPluginOptions{LocalAddr: "127.0.0.1:80"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.HTTPS2HTTPPluginOptions{}), "localAddr is required")
	require.NoError(ValidateClientPluginOptions(&v1.HTTPS2HTTPPluginOptions{LocalAddr: "127.0.0.1:80"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.HTTPS2HTTPSPluginOptions{}), "localAddr is required")
	require.NoError(ValidateClientPluginOptions(&v1.HTTPS2HTTPSPluginOptions{LocalAddr: "127.0.0.1:443"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.StaticFilePluginOptions{}), "localPath is required")
	require.NoError(ValidateClientPluginOptions(&v1.StaticFilePluginOptions{LocalPath: "/var/www"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.UnixDomainSocketPluginOptions{}), "unixPath is required")
	require.NoError(ValidateClientPluginOptions(&v1.UnixDomainSocketPluginOptions{UnixPath: "/tmp/s.sock"}))

	require.ErrorContains(ValidateClientPluginOptions(&v1.TLS2RawPluginOptions{}), "localAddr is required")
	require.NoError(ValidateClientPluginOptions(&v1.TLS2RawPluginOptions{LocalAddr: "127.0.0.1:443"}))

	require.NoError(ValidateClientPluginOptions(&v1.HTTPProxyPluginOptions{}))
	require.NoError(ValidateClientPluginOptions(&v1.Socks5PluginOptions{}))
	require.NoError(ValidateClientPluginOptions(&v1.VirtualNetPluginOptions{}))

	// 2. ValidateProxyConfigurerForClient across all proxy types and error paths
	validBase := v1.ProxyBaseConfig{
		Name: "p1",
		ProxyBackend: v1.ProxyBackend{
			LocalPort: 8080,
		},
		Transport: v1.ProxyTransport{
			BandwidthLimitMode: "client",
		},
	}

	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{}, ""), "name should not be empty")

	badBW := validBase
	badBW.Transport.BandwidthLimitMode = "invalid"
	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: badBW}, ""), "bandwidth limit mode")

	badPort := validBase
	badPort.LocalPort = 70000
	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: badPort}, ""), "localPort")

	badHC := validBase
	badHC.HealthCheck.Type = "icmp"
	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: badHC}, ""), "not support health check type")

	badHTTPPath := validBase
	badHTTPPath.HealthCheck.Type = "http"
	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: badHTTPPath}, ""), "health check path should not be empty")

	badPlugin := validBase
	badPlugin.Plugin = v1.TypedClientPluginOptions{
		Type:                v1.PluginStaticFile,
		ClientPluginOptions: &v1.StaticFilePluginOptions{},
	}
	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: badPlugin}, ""), "localPath is required")

	// TCP, STCP, XTCP, SUDP valid for client
	require.NoError(ValidateProxyConfigurerForClient(&v1.TCPProxyConfig{ProxyBaseConfig: validBase}, ""))
	require.NoError(ValidateProxyConfigurerForClient(&v1.STCPProxyConfig{ProxyBaseConfig: validBase}, ""))
	require.NoError(ValidateProxyConfigurerForClient(&v1.XTCPProxyConfig{ProxyBaseConfig: validBase}, ""))
	require.NoError(ValidateProxyConfigurerForClient(&v1.SUDPProxyConfig{ProxyBaseConfig: validBase}, ""))

	// HTTP, HTTPS, TCPMux domain & multiplexer validation for client
	require.ErrorContains(
		ValidateProxyConfigurerForClient(&v1.HTTPProxyConfig{ProxyBaseConfig: validBase}, ""),
		"subdomain and custom domains should not be both empty",
	)
	require.NoError(ValidateProxyConfigurerForClient(&v1.HTTPProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "app"},
	}, ""))

	require.ErrorContains(
		ValidateProxyConfigurerForClient(&v1.HTTPSProxyConfig{ProxyBaseConfig: validBase}, ""),
		"subdomain and custom domains should not be both empty",
	)
	require.NoError(ValidateProxyConfigurerForClient(&v1.HTTPSProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"example.com"}},
	}, ""))

	require.ErrorContains(ValidateProxyConfigurerForClient(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "mux"},
		Multiplexer:     "invalid-mux",
	}, ""), "not support multiplexer")
	require.NoError(ValidateProxyConfigurerForClient(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "mux"},
		Multiplexer:     string(v1.TCPMultiplexerHTTPConnect),
	}, ""))

	require.ErrorContains(ValidateProxyConfigurerForClient(&fakeProxyConfigurer{ProxyBaseConfig: validBase}, ""), "unknown proxy config type")

	// 3. ValidateProxyConfigurerForServer across all proxy types and server constraints
	svrCfg := &v1.ServerConfig{
		VhostHTTPPort:         80,
		VhostHTTPSPort:        443,
		TCPMuxHTTPConnectPort: 1337,
		SubDomainHost:         "frps.example.com",
	}

	require.NoError(ValidateProxyConfigurerForServer(&v1.TCPProxyConfig{ProxyBaseConfig: validBase}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.UDPProxyConfig{ProxyBaseConfig: validBase}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.STCPProxyConfig{ProxyBaseConfig: validBase}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.XTCPProxyConfig{ProxyBaseConfig: validBase}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.SUDPProxyConfig{ProxyBaseConfig: validBase}, svrCfg))
	require.ErrorContains(ValidateProxyConfigurerForServer(&fakeProxyConfigurer{ProxyBaseConfig: validBase}, svrCfg), "unknown proxy config type")

	// Server UDP datagram checks
	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.UDPProxyConfig{
		ProxyBaseConfig:    validBase,
		QUICDatagramStrict: true,
	}, svrCfg), "quicDatagramStrict requires quicDatagrams to be true")

	longNameBase := validBase
	longNameBase.Name = strings.Repeat("x", naming.MaxDatagramIdentifierLength+1)
	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.UDPProxyConfig{
		ProxyBaseConfig: longNameBase,
		QUICDatagrams:   true,
	}, svrCfg), "the quic datagram lane needs a proxy name")

	// Server HTTP / HTTPS / TCPMux port and subdomain checks
	emptySvr := &v1.ServerConfig{}
	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.HTTPProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"a.com"}},
	}, emptySvr), "vhost http port is not set")

	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.HTTPSProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"a.com"}},
	}, emptySvr), "vhost https port is not set")

	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{CustomDomains: []string{"a.com"}},
		Multiplexer:     string(v1.TCPMultiplexerHTTPConnect),
	}, emptySvr), "tcpmux with multiplexer httpconnect not supported")

	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.HTTPProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "sub"},
	}, &v1.ServerConfig{VhostHTTPPort: 80}), "subdomain is not supported")

	require.ErrorContains(ValidateProxyConfigurerForServer(&v1.HTTPProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "a.b"},
	}, svrCfg), "'.' and '*' are not supported in subdomain")

	require.NoError(ValidateProxyConfigurerForServer(&v1.HTTPProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "sub"},
	}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.HTTPSProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "sub"},
	}, svrCfg))
	require.NoError(ValidateProxyConfigurerForServer(&v1.TCPMuxProxyConfig{
		ProxyBaseConfig: validBase,
		DomainConfig:    v1.DomainConfig{SubDomain: "sub"},
		Multiplexer:     string(v1.TCPMultiplexerHTTPConnect),
	}, svrCfg))

	// 4. ValidateVisitorConfigurer and visitor plugin validation
	require.ErrorContains(ValidateVisitorConfigurer(&v1.STCPVisitorConfig{}), "name is required")
	require.ErrorContains(ValidateVisitorConfigurer(&v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{Name: "v1"},
	}), "server name is required")
	require.ErrorContains(ValidateVisitorConfigurer(&v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{Name: "v1", ServerName: "s1"},
	}), "bind port is required")

	validVisitorBase := v1.VisitorBaseConfig{Name: "v1", ServerName: "s1", BindPort: 9000}
	require.NoError(ValidateVisitorConfigurer(&v1.STCPVisitorConfig{VisitorBaseConfig: validVisitorBase}))
	require.NoError(ValidateVisitorConfigurer(&v1.SUDPVisitorConfig{VisitorBaseConfig: validVisitorBase}))
	require.NoError(ValidateVisitorConfigurer(&v1.XTCPVisitorConfig{VisitorBaseConfig: validVisitorBase, Protocol: "quic"}))
	require.ErrorContains(ValidateVisitorConfigurer(&v1.XTCPVisitorConfig{VisitorBaseConfig: validVisitorBase, Protocol: "tcp"}), "protocol should be kcp or quic")
	require.ErrorContains(ValidateVisitorConfigurer(&fakeVisitorConfigurer{VisitorBaseConfig: validVisitorBase}), "unknown visitor config type")

	badVisitorPlugin := validVisitorBase
	badVisitorPlugin.Plugin = v1.TypedVisitorPluginOptions{
		Type:                 v1.VisitorPluginVirtualNet,
		VisitorPluginOptions: &v1.VirtualNetVisitorPluginOptions{},
	}
	require.ErrorContains(ValidateVisitorConfigurer(&v1.STCPVisitorConfig{VisitorBaseConfig: badVisitorPlugin}), "destinationIP is required")
}
