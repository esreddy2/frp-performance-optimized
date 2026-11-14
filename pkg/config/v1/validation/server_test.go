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
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	splugin "github.com/fatedier/frp/pkg/plugin/server"
)

func TestValidateServerConfigMaxPoolCount(t *testing.T) {
	for _, tc := range []struct {
		name         string
		maxPoolCount int64
		wantErr      bool
	}{
		{name: "negative", maxPoolCount: -1, wantErr: true},
		{name: "zero", maxPoolCount: 0},
		{name: "positive", maxPoolCount: 5},
		{name: "maximum int64", maxPoolCount: math.MaxInt64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
			cfg.Transport.MaxPoolCount = tc.maxPoolCount
			require.NoError(t, cfg.Complete())

			_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
			if tc.wantErr {
				require.ErrorContains(t, err, "invalid transport.maxPoolCount")
				require.ErrorContains(t, err, "must be non-negative")
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateServerConfigHTTPPluginOps(t *testing.T) {
	cfg := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
	cfg.HTTPPlugins = []v1.HTTPPluginOptions{
		{
			Name: "admission",
			Addr: "127.0.0.1:9000",
			Path: "/plugin",
			Ops:  []string{splugin.OpNewProxy, splugin.OpNewProxyResult, splugin.OpCloseProxy},
		},
	}
	require.NoError(t, cfg.Complete())

	_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
	require.NoError(t, err)
}

func TestValidateServerConfigNewProxyResultRequiresCloseProxy(t *testing.T) {
	cfg := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
	cfg.HTTPPlugins = []v1.HTTPPluginOptions{
		{
			Name: "admission",
			Addr: "127.0.0.1:9000",
			Path: "/plugin",
			Ops:  []string{splugin.OpNewProxy, splugin.OpNewProxyResult},
		},
	}
	require.NoError(t, cfg.Complete())

	_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
	require.ErrorContains(t, err, "requires CloseProxy for admission rollback")
}

func TestValidateServerConfigNewProxyResultHeartbeatBudget(t *testing.T) {
	cfg := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
	cfg.HTTPPlugins = []v1.HTTPPluginOptions{
		{
			Name: "admission",
			Addr: "127.0.0.1:9000",
			Path: "/plugin",
			Ops:  []string{splugin.OpNewProxy, splugin.OpNewProxyResult, splugin.OpCloseProxy},
		},
	}
	// One NewProxy and one NewProxyResult callback cost 2 * 25s of the
	// synchronous budget, so a 40s heartbeat timeout is too small.
	cfg.Transport.HeartbeatTimeout = 40
	require.NoError(t, cfg.Complete())

	_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
	require.ErrorContains(t, err, "must exceed aggregate synchronous NewProxy callback budget")
}

func TestValidateServerConfigNewProxyResultHeartbeatBudgetWithoutHeartbeat(t *testing.T) {
	cfg := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
	cfg.HTTPPlugins = []v1.HTTPPluginOptions{
		{
			Name: "admission",
			Addr: "127.0.0.1:9000",
			Path: "/plugin",
			Ops:  []string{splugin.OpNewProxy, splugin.OpNewProxyResult, splugin.OpCloseProxy},
		},
	}
	cfg.Transport.HeartbeatTimeout = 0
	require.NoError(t, cfg.Complete())

	_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
	require.NoError(t, err)
}

func TestValidateServerConfigAdditionalContracts(t *testing.T) {
	t.Run("invalid auth method, scopes, and oidc issuer", func(t *testing.T) {
		cfg := validServerConfigWithAuth(v1.AuthServerConfig{
			Method:           "invalid",
			AdditionalScopes: []v1.AuthScope{"InvalidScope"},
		})
		require.NoError(t, cfg.Complete())
		_, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
		require.ErrorContains(t, err, "invalid auth method")
		require.ErrorContains(t, err, "invalid auth additional scopes")

		cfgOIDCEmpty := validServerConfigWithAuth(v1.AuthServerConfig{
			Method: v1.AuthMethodOIDC,
		})
		require.NoError(t, cfgOIDCEmpty.Complete())
		_, err = NewConfigValidator(nil).ValidateServerConfig(cfgOIDCEmpty)
		require.ErrorContains(t, err, "auth.oidc.issuer is required")

		cfgOIDCRel := validServerConfigWithAuth(v1.AuthServerConfig{
			Method: v1.AuthMethodOIDC,
			OIDC:   v1.AuthOIDCServerConfig{Issuer: "/relative/issuer"},
		})
		require.NoError(t, cfgOIDCRel.Complete())
		_, err = NewConfigValidator(nil).ValidateServerConfig(cfgOIDCRel)
		require.ErrorContains(t, err, "auth.oidc.issuer must be an absolute URL")
	})

	t.Run("log level, webServer TLS, useSystemCa, quic, httpPlugin ops, and requireKeyShare warning", func(t *testing.T) {
		cfg := validServerConfigWithAuth(v1.AuthServerConfig{
			Method: v1.AuthMethodOIDC,
			OIDC:   v1.AuthOIDCServerConfig{Issuer: "https://idp.example.com"},
		})
		require.NoError(t, cfg.Complete())
		cfg.Log.Level = "invalid_level"
		cfg.WebServer.TLS = &v1.TLSConfig{CertFile: "only_cert.pem"}
		cfg.Transport.TLS.UseSystemCa = true
		cfg.Transport.QUIC.KeepalivePeriod = -1
		cfg.HTTPPlugins = []v1.HTTPPluginOptions{
			{Name: "badop", Ops: []string{"UnknownOp"}},
		}

		warn, err := NewConfigValidator(nil).ValidateServerConfig(cfg)
		require.ErrorContains(t, err, "invalid log level")
		require.ErrorContains(t, err, "tls.keyFile must be specified")
		require.ErrorContains(t, err, "transport.tls.useSystemCa is only supported in frpc")
		require.ErrorContains(t, err, "invalid transport.quic options")
		require.ErrorContains(t, err, "invalid http plugin ops")
		require.ErrorContains(t, warn, "transport.requireKeyShare is false on unencrypted server")

		// WebServer missing certFile
		cfg2 := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
		require.NoError(t, cfg2.Complete())
		cfg2.WebServer.TLS = &v1.TLSConfig{}
		_, err = NewConfigValidator(nil).ValidateServerConfig(cfg2)
		require.ErrorContains(t, err, "tls.certFile must be specified")

		// WebServer UseSystemCa
		cfg3 := validServerConfigWithAuth(v1.AuthServerConfig{Method: v1.AuthMethodToken})
		require.NoError(t, cfg3.Complete())
		cfg3.WebServer.TLS = &v1.TLSConfig{UseSystemCa: true}
		_, err = NewConfigValidator(nil).ValidateServerConfig(cfg3)
		require.ErrorContains(t, err, "webServer.tls.useSystemCa is only supported in frpc")
	})
}
