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

package sub

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/policy/security"
)

func TestVerifyClientConfigFeatureGates(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "VirtualNet enabled",
			content: `featureGates = { VirtualNet = true }
virtualNet.address = "100.86.0.4/24"
`,
		},
		{
			name: "VirtualNet disabled",
			content: `featureGates = { VirtualNet = false }
virtualNet.address = "100.86.0.4/24"
`,
			wantErr: "VirtualNet feature is not enabled",
		},
		{
			name:    "unknown feature gate",
			content: `featureGates = { UnknownFeature = true }`,
			wantErr: "unrecognized feature gate: UnknownFeature",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configFile := filepath.Join(t.TempDir(), "frpc.toml")
			require.NoError(t, os.WriteFile(configFile, []byte(tc.content), 0o600))

			warning, err := verifyClientConfig(configFile, true, security.NewUnsafeFeatures(nil))
			require.NoError(t, warning)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestAdminHandlersAndSubcommands(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tcp":[{"name":"ssh","type":"tcp","status":"running","local_addr":"127.0.0.1:22","remote_addr":"127.0.0.1:6000"}]}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	clientCfg := &v1.ClientCommonConfig{
		WebServer: v1.WebServerConfig{
			Addr:     host,
			Port:     port,
			User:     "admin",
			Password: "secret",
		},
	}

	require.NoError(t, ReloadHandler(clientCfg))
	require.NoError(t, StatusHandler(clientCfg))
	require.NoError(t, StopHandler(clientCfg))

	// Error when server is unreachable
	badCfg := &v1.ClientCommonConfig{
		WebServer: v1.WebServerConfig{
			Addr: "127.0.0.1",
			Port: 1,
		},
	}
	require.Error(t, ReloadHandler(badCfg))
	require.Error(t, StatusHandler(badCfg))
	require.Error(t, StopHandler(badCfg))
}

func TestValidateNatHoleAndVerifyCommand(t *testing.T) {
	require.ErrorContains(t, validateForNatHoleDiscovery(&v1.ClientCommonConfig{}), "nat_hole_stun_server can not be empty")
	require.NoError(t, validateForNatHoleDiscovery(&v1.ClientCommonConfig{NatHoleSTUNServer: "stun.example.com:3478"}))

	origCfgFile := cfgFile
	origShowVersion := showVersion
	origCfgDir := cfgDir
	t.Cleanup(func() {
		cfgFile = origCfgFile
		showVersion = origShowVersion
		cfgDir = origCfgDir
	})

	// 1. rootCmd --version
	showVersion = true
	require.NoError(t, rootCmd.RunE(rootCmd, nil))
	showVersion = false

	// 2. verifyCmd with empty cfgFile
	cfgFile = ""
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))

	// 3. verifyCmd with valid config file (and warning)
	tmpCfg := filepath.Join(t.TempDir(), "frpc.toml")
	cfgContent := `serverAddr = "127.0.0.1"
serverPort = 7000
transport.protocol = "tcp"
transport.tls.enable = false
transport.tls.certFile = "unused.crt"

[[proxies]]
name = "web"
type = "tcp"
localPort = 8080
remotePort = 6000
`
	require.NoError(t, os.WriteFile(tmpCfg, []byte(cfgContent), 0o600))
	cfgFile = tmpCfg
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))

	// 4. verifyClientConfig with nonexistent file returns error
	_, err := verifyClientConfig(filepath.Join(t.TempDir(), "missing.toml"), true, nil)
	require.Error(t, err)

	// 5. NewAdminCommand execution against valid config file
	mux := http.NewServeMux()
	mux.HandleFunc("/api/reload", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	adminCfgFile := filepath.Join(t.TempDir(), "admin.toml")
	require.NoError(t, os.WriteFile(adminCfgFile, []byte("webServer.addr = \""+host+"\"\nwebServer.port = "+portStr+"\n"), 0o600))
	cfgFile = adminCfgFile
	adminCmd := NewAdminCommand("reload", "test reload", ReloadHandler)
	adminCmd.Run(adminCmd, nil)

	// 6. runClient and runMultipleClients (via rootCmd with cfgDir)
	require.Error(t, runClient(filepath.Join(t.TempDir(), "nonexistent.toml"), nil))

	// Legacy INI format with invalid proxy triggers legacy warning then validation error in runClientWithAggregator
	dir := t.TempDir()
	iniFile := filepath.Join(dir, "legacy.ini")
	iniContent := `[common]
server_addr = 127.0.0.1
server_port = 7000
tls_enable = false
tls_cert_file = unused.crt

[bad_tcp]
type = tcp
local_port = -1
`
	require.NoError(t, os.WriteFile(iniFile, []byte(iniContent), 0o600))
	require.Error(t, runClient(iniFile, security.NewUnsafeFeatures(nil)))

	// Store enabled with relative path + validation error exercises StoreSource setup in runClientWithAggregator
	storeCfgFile := filepath.Join(dir, "store_frpc.toml")
	storeCfgContent := `serverAddr = "127.0.0.1"
serverPort = 7000
store.path = "substore/store.json"

[[proxies]]
name = "invalid-tcp"
type = "tcp"
localPort = -1
`
	require.NoError(t, os.WriteFile(storeCfgFile, []byte(storeCfgContent), 0o600))
	require.Error(t, runClient(storeCfgFile, security.NewUnsafeFeatures(nil)))

	// rootCmd with cfgDir runs runMultipleClients across files in dir
	cfgDir = dir
	require.NoError(t, rootCmd.RunE(rootCmd, nil))
	cfgDir = ""

	// 7. startService with empty proxy name fails in configSource.ReplaceAll
	common := &v1.ClientCommonConfig{}
	require.NoError(t, common.Complete())
	unnamedProxy := &v1.TCPProxyConfig{ProxyBaseConfig: v1.ProxyBaseConfig{Name: "", Type: "tcp"}}
	require.ErrorContains(t, startService(common, []v1.ProxyConfigurer{unnamedProxy}, nil, nil, ""), "failed to set config source")
}
