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
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/policy/featuregate"
	"github.com/fatedier/frp/pkg/policy/security"
)

func validateClientFeatureGates(t *testing.T, gates map[string]bool, virtualNetAddress string) error {
	t.Helper()

	cfg := &v1.ClientCommonConfig{
		FeatureGates: gates,
		VirtualNet: v1.VirtualNetConfig{
			Address: virtualNetAddress,
		},
	}
	require.NoError(t, cfg.Complete())

	_, err := NewConfigValidator(security.NewUnsafeFeatures(nil)).ValidateClientCommonConfig(cfg)
	return err
}

func TestValidateTransportUseSystemCaRequiresEnabledTLS(t *testing.T) {
	// wss and quic always run over TLS, so the system roots are used there
	// even when transport.tls.enable is false. The other protocols ignore
	// useSystemCa while TLS is off, so it stays an error instead of silently
	// dropping the verification the user asked for.
	disabled := false
	for _, protocol := range []string{"wss", "quic"} {
		cfg := &v1.ClientTransportConfig{Protocol: protocol}
		cfg.TLS.Enable = &disabled
		cfg.TLS.UseSystemCa = true
		cfg.Complete()

		warning, err := validateTransportConfig(cfg)
		require.NoError(t, err)
		require.NoError(t, warning)
	}

	for _, protocol := range []string{"tcp", "kcp", "websocket"} {
		cfg := &v1.ClientTransportConfig{Protocol: protocol}
		cfg.TLS.Enable = &disabled
		cfg.TLS.UseSystemCa = true
		cfg.Complete()

		_, err := validateTransportConfig(cfg)
		require.ErrorContains(t, err, "transport.tls.useSystemCa requires transport.tls.enable to be true")
	}
}

func TestValidateClientFeatureGates(t *testing.T) {
	tests := []struct {
		name              string
		featureGates      map[string]bool
		virtualNetAddress string
		wantErr           string
	}{
		{
			name:              "VirtualNet enabled",
			featureGates:      map[string]bool{"VirtualNet": true},
			virtualNetAddress: "100.86.0.4/24",
		},
		{
			name:              "VirtualNet explicitly disabled",
			featureGates:      map[string]bool{"VirtualNet": false},
			virtualNetAddress: "100.86.0.4/24",
			wantErr:           "VirtualNet feature is not enabled",
		},
		{
			name:              "VirtualNet disabled by default",
			virtualNetAddress: "100.86.0.4/24",
			wantErr:           "VirtualNet feature is not enabled",
		},
		{
			name:         "unknown feature gate",
			featureGates: map[string]bool{"UnknownFeature": true},
			wantErr:      "unrecognized feature gate: UnknownFeature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClientFeatureGates(t, tc.featureGates, tc.virtualNetAddress)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestGetClientConfigRequirements(t *testing.T) {
	virtualNetProxy := &v1.STCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			ProxyBackend: v1.ProxyBackend{
				Plugin: v1.TypedClientPluginOptions{Type: v1.PluginVirtualNet},
			},
		},
	}
	virtualNetVisitor := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Plugin: v1.TypedVisitorPluginOptions{Type: v1.VisitorPluginVirtualNet},
		},
	}

	tests := []struct {
		name     string
		common   *v1.ClientCommonConfig
		proxies  []v1.ProxyConfigurer
		visitors []v1.VisitorConfigurer
		wantVNet bool
	}{
		{name: "no requirements"},
		{
			name:     "common VirtualNet address",
			common:   &v1.ClientCommonConfig{VirtualNet: v1.VirtualNetConfig{Address: "100.86.0.4/24"}},
			wantVNet: true,
		},
		{name: "VirtualNet proxy", proxies: []v1.ProxyConfigurer{virtualNetProxy}, wantVNet: true},
		{name: "VirtualNet visitor", visitors: []v1.VisitorConfigurer{virtualNetVisitor}, wantVNet: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := GetClientConfigRequirements(tc.common, tc.proxies, tc.visitors)
			require.Equal(t, tc.wantVNet, got.VirtualNet)
		})
	}
}

func TestValidateClientFeatureGatesAreConfigScoped(t *testing.T) {
	defaultGatesBefore := featuregate.DefaultFeatureGates.String()

	require.NoError(t, validateClientFeatureGates(
		t,
		map[string]bool{"VirtualNet": true},
		"100.86.0.4/24",
	))
	require.Equal(t, defaultGatesBefore, featuregate.DefaultFeatureGates.String())

	err := validateClientFeatureGates(
		t,
		map[string]bool{"VirtualNet": false},
		"100.86.0.4/24",
	)
	require.ErrorContains(t, err, "VirtualNet feature is not enabled")
	require.Equal(t, defaultGatesBefore, featuregate.DefaultFeatureGates.String())
}

func TestValidateClientAuthAndOIDC(t *testing.T) {
	t.Run("invalid auth method and scopes", func(t *testing.T) {
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Auth.Method = "invalid"
		cfg.Auth.AdditionalScopes = []v1.AuthScope{"InvalidScope"}

		_, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.ErrorContains(t, err, "invalid auth method")
		require.ErrorContains(t, err, "invalid auth additional scopes")
	})

	t.Run("oidc client credentials validation", func(t *testing.T) {
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Auth.Method = v1.AuthMethodOIDC

		_, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.Error(t, err)
	})

	t.Run("oidc tokenSource mutual exclusivity and exec unsafe feature", func(t *testing.T) {
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Auth.Method = v1.AuthMethodOIDC
		cfg.Auth.OIDC.ClientID = "id"
		cfg.Auth.OIDC.TokenSource = &v1.ValueSource{
			Type: "exec",
		}

		_, err := NewConfigValidator(security.NewUnsafeFeatures(nil)).ValidateClientCommonConfig(cfg)
		require.ErrorContains(t, err, "cannot specify both auth.oidc.tokenSource and any other field of auth.oidc")
		require.ErrorContains(t, err, "TokenSourceExec")
		require.ErrorContains(t, err, "invalid auth.oidc.tokenSource")
	})
}

func TestValidateClientTransportAndIncludeFiles(t *testing.T) {
	t.Run("heartbeat timeout less than interval", func(t *testing.T) {
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Transport.HeartbeatInterval = 30
		cfg.Transport.HeartbeatTimeout = 10

		_, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.ErrorContains(t, err, "invalid transport.heartbeatTimeout")
	})

	t.Run("tls files warning when tls disabled", func(t *testing.T) {
		disabled := false
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Transport.Protocol = "tcp"
		cfg.Transport.TLS.Enable = &disabled
		cfg.Transport.TLS.CertFile = "cert.pem"
		cfg.Transport.TLS.KeyFile = "key.pem"
		cfg.Transport.TLS.TrustedCaFile = "ca.pem"

		warn, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.NoError(t, err)
		require.ErrorContains(t, warn, "transport.tls.certFile is invalid when transport.tls.enable is false")
		require.ErrorContains(t, warn, "transport.tls.keyFile is invalid when transport.tls.enable is false")
		require.ErrorContains(t, warn, "transport.tls.trustedCaFile is invalid when transport.tls.enable is false")
	})

	t.Run("invalid protocol, wireProtocol, quic options, tcp buffer options", func(t *testing.T) {
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Transport.Protocol = "invalid"
		cfg.Transport.WireProtocol = "v99"
		cfg.Transport.TCPNotSentLowat = -1

		_, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.ErrorContains(t, err, "invalid transport.protocol")
		require.ErrorContains(t, err, "invalid transport.wireProtocol")
		require.ErrorContains(t, err, "invalid transport.tcpNotSentLowat")

		cfgQuic := &v1.ClientCommonConfig{}
		require.NoError(t, cfgQuic.Complete())
		cfgQuic.Transport.Protocol = "quic"
		cfgQuic.Transport.QUIC.KeepalivePeriod = -1
		_, err = NewConfigValidator(nil).ValidateClientCommonConfig(cfgQuic)
		require.ErrorContains(t, err, "invalid transport.quic options")
	})

	t.Run("wireProtocol v2 security warning", func(t *testing.T) {
		disabled := false
		cfg := &v1.ClientCommonConfig{}
		require.NoError(t, cfg.Complete())
		cfg.Transport.Protocol = "tcp"
		cfg.Transport.WireProtocol = "v2"
		cfg.Transport.RequireKeyShare = false
		cfg.Transport.TLS.Enable = &disabled
		cfg.Auth.Method = v1.AuthMethodOIDC
		cfg.Auth.OIDC.ClientID = "id"
		cfg.Auth.OIDC.ClientSecret = "secret"
		cfg.Auth.OIDC.TokenEndpointURL = "https://idp.example.com/token"

		warn, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.NoError(t, err)
		require.ErrorContains(t, warn, "transport.wireProtocol is 'v2' over unencrypted transport")
	})

	t.Run("include files directory validation", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &v1.ClientCommonConfig{
			IncludeConfigFiles: []string{dir + "/*.toml", "/nonexistent_dir_frp_test_12345/*.toml"},
		}
		require.NoError(t, cfg.Complete())

		_, err := NewConfigValidator(nil).ValidateClientCommonConfig(cfg)
		require.ErrorContains(t, err, "not exist")
	})
}

func TestValidateAllClientConfig(t *testing.T) {
	common := &v1.ClientCommonConfig{User: "alice"}
	require.NoError(t, common.Complete())

	tcpProxy := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "p1",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				LocalPort: 8080,
			},
		},
	}
	tcpProxy.Complete()

	stcpVisitor := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name:       "v1",
			Type:       "stcp",
			ServerName: "s1",
			BindPort:   9000,
		},
	}
	stcpVisitor.Complete()

	warn, err := ValidateAllClientConfig(common, []v1.ProxyConfigurer{tcpProxy}, []v1.VisitorConfigurer{stcpVisitor}, nil)
	require.NoError(t, err)
	require.NoError(t, warn)

	// UDP proxy with QUICDatagrams on non-quic transport fails
	udpProxy := &v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "u1",
			Type: "udp",
			ProxyBackend: v1.ProxyBackend{
				LocalPort: 5353,
			},
		},
		QUICDatagrams: true,
	}
	udpProxy.Complete()
	_, err = ValidateAllClientConfig(common, []v1.ProxyConfigurer{udpProxy}, nil, nil)
	require.ErrorContains(t, err, "quicDatagrams requires transport.protocol to be quic")

	// Invalid proxy fails
	badProxy := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "bad",
			Type: "tcp",
		},
	}
	_, err = ValidateAllClientConfig(common, []v1.ProxyConfigurer{badProxy}, nil, nil)
	require.ErrorContains(t, err, "proxy bad:")

	// Invalid visitor fails
	badVisitor := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{
			Name: "badv",
			Type: "stcp",
		},
	}
	_, err = ValidateAllClientConfig(common, nil, []v1.VisitorConfigurer{badVisitor}, nil)
	require.ErrorContains(t, err, "visitor badv:")
}
