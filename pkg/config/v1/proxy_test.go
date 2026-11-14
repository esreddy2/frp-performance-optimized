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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	"github.com/fatedier/frp/pkg/msg"
)

func TestUnmarshalTypedProxyConfig(t *testing.T) {
	require := require.New(t)
	proxyConfigs := struct {
		Proxies []TypedProxyConfig `json:"proxies,omitempty"`
	}{}

	strs := `{
		"proxies": [
			{
				"type": "tcp",
				"localPort": 22,
				"remotePort": 6000
			},
			{
				"type": "http",
				"localPort": 80,
				"customDomains": ["www.example.com"]
			}
		]
	}`
	err := json.Unmarshal([]byte(strs), &proxyConfigs)
	require.NoError(err)

	require.IsType(&TCPProxyConfig{}, proxyConfigs.Proxies[0].ProxyConfigurer)
	require.IsType(&HTTPProxyConfig{}, proxyConfigs.Proxies[1].ProxyConfigurer)
}

func TestAllProxyTypesMarshalUnmarshalCloneAndComplete(t *testing.T) {
	require := require.New(t)

	bw, err := types.NewBandwidthQuantity("2MB")
	require.NoError(err)

	base := ProxyBaseConfig{
		Name:        "p-base",
		Annotations: map[string]string{"env": "prod"},
		Metadatas:   map[string]string{"owner": "team"},
		Transport: ProxyTransport{
			UseEncryption:      true,
			UseCompression:     true,
			BandwidthLimit:     bw,
			BandwidthLimitMode: "server",
		},
		LoadBalancer: LoadBalancerConfig{
			Group:    "g1",
			GroupKey: "gk1",
		},
	}

	t.Run("TCPProxyConfig", func(t *testing.T) {
		p := &TCPProxyConfig{ProxyBaseConfig: base, RemotePort: 6001}
		p.Type = string(ProxyTypeTCP)
		p.Complete()
		require.Equal("127.0.0.1", p.LocalIP)

		var m msg.NewProxy
		p.MarshalToMsg(&m)
		var restored TCPProxyConfig
		restored.UnmarshalFromMsg(&m)
		require.Equal(p.Name, restored.Name)
		require.Equal(p.RemotePort, restored.RemotePort)
		require.Equal(p.Transport.UseEncryption, restored.Transport.UseEncryption)
		require.Equal(p.Transport.UseCompression, restored.Transport.UseCompression)
		require.True(p.Transport.BandwidthLimit.Equal(&restored.Transport.BandwidthLimit))
		require.Equal("server", restored.Transport.BandwidthLimitMode)
		require.Equal("g1", restored.LoadBalancer.Group)
		require.Equal("gk1", restored.LoadBalancer.GroupKey)

		cloned := p.Clone().(*TCPProxyConfig)
		cloned.RemotePort = 7000
		require.Equal(6001, p.RemotePort)
	})

	t.Run("UDPProxyConfig", func(t *testing.T) {
		p := &UDPProxyConfig{
			ProxyBaseConfig:    base,
			RemotePort:         6002,
			QUICDatagrams:      true,
			QUICDatagramStrict: true,
		}
		p.Type = string(ProxyTypeUDP)
		p.Transport.ProxyProtocolVersion = "v2"
		p.Complete()
		require.Equal("v2", p.Transport.ProxyProtocol)
		require.Equal("first-packet", p.Transport.ProxyProtocolMode)
		require.Equal(0, p.Transport.SocketMark)

		var m msg.NewProxy
		p.MarshalToMsg(&m)
		var restored UDPProxyConfig
		restored.UnmarshalFromMsg(&m)
		require.Equal(6002, restored.RemotePort)
		require.True(restored.QUICDatagrams)
		require.True(restored.QUICDatagramStrict)

		cloned := p.Clone().(*UDPProxyConfig)
		cloned.QUICDatagrams = false
		require.True(p.QUICDatagrams)
	})

	t.Run("HTTPProxyConfig", func(t *testing.T) {
		p := &HTTPProxyConfig{
			ProxyBaseConfig:   base,
			DomainConfig:      DomainConfig{CustomDomains: []string{"app.example.com"}, SubDomain: "app"},
			Locations:         []string{"/v1"},
			HTTPUser:          "u",
			HTTPPassword:      "pw",
			HostHeaderRewrite: "internal.local",
			RequestHeaders:    HeaderOperations{Set: map[string]string{"X-Req": "1"}},
			ResponseHeaders:   HeaderOperations{Set: map[string]string{"X-Resp": "2"}},
			RouteByHTTPUser:   "u",
		}
		p.Type = string(ProxyTypeHTTP)
		p.Transport.ProxyProtocol = "tproxy"
		p.Complete()
		require.Equal(1, p.Transport.SocketMark)
		require.Equal("tproxy", p.Transport.ProxyProtocolVersion)

		var m msg.NewProxy
		p.MarshalToMsg(&m)
		var restored HTTPProxyConfig
		restored.UnmarshalFromMsg(&m)
		require.Equal(p.CustomDomains, restored.CustomDomains)
		require.Equal(p.SubDomain, restored.SubDomain)
		require.Equal(p.Locations, restored.Locations)
		require.Equal(p.HTTPUser, restored.HTTPUser)
		require.Equal(p.HTTPPassword, restored.HTTPPassword)
		require.Equal(p.HostHeaderRewrite, restored.HostHeaderRewrite)
		require.Equal(p.RequestHeaders.Set, restored.RequestHeaders.Set)
		require.Equal(p.ResponseHeaders.Set, restored.ResponseHeaders.Set)
		require.Equal(p.RouteByHTTPUser, restored.RouteByHTTPUser)
	})

	t.Run("HTTPSProxyConfig", func(t *testing.T) {
		p := &HTTPSProxyConfig{
			ProxyBaseConfig: base,
			DomainConfig:    DomainConfig{CustomDomains: []string{"sec.example.com"}, SubDomain: "sec"},
		}
		p.Type = string(ProxyTypeHTTPS)
		p.Complete()

		var m msg.NewProxy
		p.MarshalToMsg(&m)
		var restored HTTPSProxyConfig
		restored.UnmarshalFromMsg(&m)
		require.Equal(p.CustomDomains, restored.CustomDomains)
		require.Equal(p.SubDomain, restored.SubDomain)

		cloned := p.Clone().(*HTTPSProxyConfig)
		cloned.CustomDomains[0] = "changed.example.com"
		require.Equal("sec.example.com", p.CustomDomains[0])
	})

	t.Run("TCPMuxProxyConfig", func(t *testing.T) {
		p := &TCPMuxProxyConfig{
			ProxyBaseConfig: base,
			DomainConfig:    DomainConfig{CustomDomains: []string{"mux.example.com"}, SubDomain: "mux"},
			HTTPUser:        "u",
			HTTPPassword:    "pw",
			RouteByHTTPUser: "u",
			Multiplexer:     string(TCPMultiplexerHTTPConnect),
		}
		p.Type = string(ProxyTypeTCPMUX)
		p.Complete()

		var m msg.NewProxy
		p.MarshalToMsg(&m)
		var restored TCPMuxProxyConfig
		restored.UnmarshalFromMsg(&m)
		require.Equal(p.Multiplexer, restored.Multiplexer)
		require.Equal(p.HTTPUser, restored.HTTPUser)
		require.Equal(p.HTTPPassword, restored.HTTPPassword)
		require.Equal(p.RouteByHTTPUser, restored.RouteByHTTPUser)

		cloned := p.Clone().(*TCPMuxProxyConfig)
		cloned.CustomDomains[0] = "changed"
		require.Equal("mux.example.com", p.CustomDomains[0])
	})

	t.Run("STCP_XTCP_SUDP", func(t *testing.T) {
		stcp := &STCPProxyConfig{ProxyBaseConfig: base, Secretkey: "sk1", AllowUsers: []string{"u1"}}
		var m1 msg.NewProxy
		stcp.MarshalToMsg(&m1)
		var rStcp STCPProxyConfig
		rStcp.UnmarshalFromMsg(&m1)
		require.Equal("sk1", rStcp.Secretkey)
		require.Equal([]string{"u1"}, rStcp.AllowUsers)
		clonedStcp := stcp.Clone().(*STCPProxyConfig)
		clonedStcp.AllowUsers[0] = "u2"
		require.Equal("u1", stcp.AllowUsers[0])

		xtcp := &XTCPProxyConfig{
			ProxyBaseConfig: base,
			Secretkey:       "sk2",
			AllowUsers:      []string{"u1"},
			NatTraversal:    &NatTraversalConfig{DisableAssistedAddrs: true},
		}
		var m2 msg.NewProxy
		xtcp.MarshalToMsg(&m2)
		var rXtcp XTCPProxyConfig
		rXtcp.UnmarshalFromMsg(&m2)
		require.Equal("sk2", rXtcp.Secretkey)
		require.Equal([]string{"u1"}, rXtcp.AllowUsers)
		clonedXtcp := xtcp.Clone().(*XTCPProxyConfig)
		clonedXtcp.NatTraversal.DisableAssistedAddrs = false
		require.True(xtcp.NatTraversal.DisableAssistedAddrs)

		sudp := &SUDPProxyConfig{ProxyBaseConfig: base, Secretkey: "sk3", AllowUsers: []string{"u1"}}
		var m3 msg.NewProxy
		sudp.MarshalToMsg(&m3)
		var rSudp SUDPProxyConfig
		rSudp.UnmarshalFromMsg(&m3)
		require.Equal("sk3", rSudp.Secretkey)
		require.Equal([]string{"u1"}, rSudp.AllowUsers)
		clonedSudp := sudp.Clone().(*SUDPProxyConfig)
		clonedSudp.AllowUsers[0] = "u2"
		require.Equal("u1", sudp.AllowUsers[0])
	})
}

func TestPluginsVisitorsDecodeAndConfigCompletion(t *testing.T) {
	require := require.New(t)

	// 1. All client plugin options Complete, Clone, and nil Clone
	allPlugins := []ClientPluginOptions{
		&HTTP2HTTPSPluginOptions{LocalAddr: "127.0.0.1:8080", RequestHeaders: HeaderOperations{Set: map[string]string{"a": "b"}}},
		&HTTPProxyPluginOptions{HTTPUser: "u"},
		&HTTPS2HTTPPluginOptions{LocalAddr: "127.0.0.1:8080"},
		&HTTPS2HTTPSPluginOptions{LocalAddr: "127.0.0.1:8443"},
		&HTTP2HTTPPluginOptions{LocalAddr: "127.0.0.1:8080"},
		&Socks5PluginOptions{Username: "u"},
		&StaticFilePluginOptions{LocalPath: "/tmp"},
		&UnixDomainSocketPluginOptions{UnixPath: "/tmp/s.sock"},
		&TLS2RawPluginOptions{LocalAddr: "127.0.0.1:443"},
		&VirtualNetPluginOptions{},
	}
	for _, p := range allPlugins {
		p.Complete()
		cloned := p.Clone()
		require.NotNil(cloned)
	}
	require.Nil((*HTTP2HTTPSPluginOptions)(nil).Clone())
	require.Nil((*HTTPProxyPluginOptions)(nil).Clone())
	require.Nil((*HTTPS2HTTPPluginOptions)(nil).Clone())
	require.Nil((*HTTPS2HTTPSPluginOptions)(nil).Clone())
	require.Nil((*HTTP2HTTPPluginOptions)(nil).Clone())
	require.Nil((*Socks5PluginOptions)(nil).Clone())
	require.Nil((*StaticFilePluginOptions)(nil).Clone())
	require.Nil((*UnixDomainSocketPluginOptions)(nil).Clone())
	require.Nil((*TLS2RawPluginOptions)(nil).Clone())
	require.Nil((*VirtualNetPluginOptions)(nil).Clone())
	require.Nil((*VirtualNetVisitorPluginOptions)(nil).Clone())

	// 2. ProxyBaseConfig with plugin calls Plugin.Complete()
	pb := ProxyBaseConfig{
		Type: "tcp",
		ProxyBackend: ProxyBackend{
			Plugin: TypedClientPluginOptions{
				Type:                PluginHTTPS2HTTPS,
				ClientPluginOptions: &HTTPS2HTTPSPluginOptions{LocalAddr: "127.0.0.1:8443"},
			},
		},
	}
	pb.Complete()
	require.NotNil(pb.Plugin.ClientPluginOptions.(*HTTPS2HTTPSPluginOptions).EnableHTTP2)
	require.True(*pb.Plugin.ClientPluginOptions.(*HTTPS2HTTPSPluginOptions).EnableHTTP2)

	// 3. Visitors: NewVisitorConfigurerByType, Complete, Clone, TypedVisitorConfig JSON
	require.Nil(NewProxyConfigurerByType("nonexistent"))
	require.Nil(NewVisitorConfigurerByType("nonexistent"))

	for _, vt := range []VisitorType{VisitorTypeSTCP, VisitorTypeSUDP, VisitorTypeXTCP} {
		vc := NewVisitorConfigurerByType(vt)
		require.NotNil(vc)
		vc.Complete()
		require.Equal("127.0.0.1", vc.GetBaseConfig().BindAddr)
		require.NotNil(vc.Clone())
	}

	xtcpV := NewVisitorConfigurerByType(VisitorTypeXTCP).(*XTCPVisitorConfig)
	xtcpV.Complete()
	require.Equal("quic", xtcpV.Protocol)
	require.Equal(8, xtcpV.MaxRetriesAnHour)
	require.Equal(90, xtcpV.MinRetryInterval)
	require.Equal(1000, xtcpV.FallbackTimeoutMs)

	// 4. DecodeClientConfigJSON with visitors and error cases
	clientJSON := []byte(`{
		"serverAddr": "10.0.0.1",
		"proxies": [{"name": "t1", "type": "tcp", "localPort": 22}],
		"visitors": [{"name": "v1", "type": "xtcp", "serverName": "s1", "bindPort": 9000, "plugin": {"type": "virtual_net", "destinationIP": "10.0.0.2"}}]
	}`)
	decodedClient, err := DecodeClientConfigJSON(clientJSON, DecodeOptions{DisallowUnknownFields: true})
	require.NoError(err)
	require.Len(decodedClient.Proxies, 1)
	require.Len(decodedClient.Visitors, 1)
	require.Equal("virtual_net", decodedClient.Visitors[0].GetBaseConfig().Plugin.Type)

	// MarshalJSON round-trip on TypedProxyConfig, TypedVisitorConfig, TypedClientPluginOptions, TypedVisitorPluginOptions
	pBytes, err := json.Marshal(&decodedClient.Proxies[0])
	require.NoError(err)
	require.Contains(string(pBytes), `"t1"`)

	vBytes, err := json.Marshal(&decodedClient.Visitors[0])
	require.NoError(err)
	require.Contains(string(vBytes), `"v1"`)

	// Error cases in Decode*
	_, err = DecodeProxyConfigurerJSON(nil, DecodeOptions{})
	require.ErrorContains(err, "type is required")
	_, err = DecodeProxyConfigurerJSON([]byte(`{"type":"invalid"}`), DecodeOptions{})
	require.ErrorContains(err, "unknown proxy type")
	_, err = DecodeVisitorConfigurerJSON(nil, DecodeOptions{})
	require.ErrorContains(err, "type is required")
	_, err = DecodeVisitorConfigurerJSON([]byte(`{"type":"invalid"}`), DecodeOptions{})
	require.ErrorContains(err, "unknown visitor type")
	_, err = DecodeClientPluginOptionsJSON([]byte(`{}`), DecodeOptions{})
	require.ErrorContains(err, "plugin type is empty")
	_, err = DecodeClientPluginOptionsJSON([]byte(`{"type":"bad"}`), DecodeOptions{})
	require.ErrorContains(err, "unknown plugin type")
	_, err = DecodeVisitorPluginOptionsJSON([]byte(`{}`), DecodeOptions{})
	require.ErrorContains(err, "visitor plugin type is empty")
	_, err = DecodeVisitorPluginOptionsJSON([]byte(`{"type":"bad"}`), DecodeOptions{})
	require.ErrorContains(err, "unknown visitor plugin type")

	// 5. ClientTransportConfig with TCPMux=false and UsesImplicitTLS, ServerConfig with HTTPPlugins/TLS, StoreConfig
	falseVal := false
	ct := ClientTransportConfig{TCPMux: &falseVal, Protocol: "wss"}
	ct.Complete()
	require.Equal(int64(30), ct.HeartbeatInterval)
	require.Equal(int64(90), ct.HeartbeatTimeout)
	require.True(ct.UsesImplicitTLS())

	sc := ServerConfig{
		WebServer:   WebServerConfig{Port: 7500},
		HTTPPlugins: []HTTPPluginOptions{{Name: "p1", Addr: "127.0.0.1:9000"}},
		Transport: ServerTransportConfig{
			TCPMux: &falseVal,
			TLS:    TLSServerConfig{TLSConfig: TLSConfig{TrustedCaFile: "/path/to/ca"}},
		},
	}
	require.NoError(sc.Complete())
	require.True(sc.Transport.TLS.Force)
	require.Equal(int64(90), sc.Transport.HeartbeatTimeout)
	require.True(*sc.HTTPPlugins[0].TLSVerify)

	storeCfg := StoreConfig{Path: "/tmp/store.json"}
	require.True(storeCfg.IsEnabled())
	require.False((&StoreConfig{}).IsEnabled())
}
