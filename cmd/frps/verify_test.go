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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestFrpsRootVersionAndVerifyCmd(t *testing.T) {
	origCfgFile := cfgFile
	origShowVersion := showVersion
	origStrict := strictConfigMode
	t.Cleanup(func() {
		cfgFile = origCfgFile
		showVersion = origShowVersion
		strictConfigMode = origStrict
	})

	// 1. rootCmd with --version
	showVersion = true
	require.NoError(t, rootCmd.RunE(rootCmd, nil))
	showVersion = false

	// 2. verifyCmd without config file specified must return an error
	cfgFile = ""
	require.Error(t, verifyCmd.RunE(verifyCmd, nil))

	// 3. verifyCmd with valid TOML config (with warning when requireKeyShare=false on unencrypted server)
	validCfg := filepath.Join(t.TempDir(), "frps.toml")
	content := `bindPort = 7000
auth.method = "oidc"
auth.oidc.issuer = "https://idp.example.com"
transport.requireKeyShare = false
`
	require.NoError(t, os.WriteFile(validCfg, []byte(content), 0o600))
	cfgFile = validCfg
	strictConfigMode = true
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))

	// 4. runServer returns error when server.NewService fails (e.g., invalid bindAddr)
	badServerCfg := &v1.ServerConfig{
		BindAddr: "999.999.999.999",
		BindPort: 7000,
	}
	require.NoError(t, badServerCfg.Complete())
	cfgFile = ""
	require.Error(t, runServer(badServerCfg))
	cfgFile = validCfg
	require.Error(t, runServer(badServerCfg))
}

func TestMergeServerConfigFlags(t *testing.T) {
	dst := &v1.ServerConfig{
		BindAddr: "0.0.0.0",
		BindPort: 7000,
	}
	src := &v1.ServerConfig{
		BindAddr: "127.0.0.1",
		BindPort: 9000,
	}

	cmd := &cobra.Command{Use: "test"}
	var boundCfg v1.ServerConfig
	config.RegisterServerConfigFlags(cmd, &boundCfg)

	// Simulate setting flags on CLI
	require.NoError(t, cmd.PersistentFlags().Set("bind_addr", "127.0.0.1"))
	require.NoError(t, cmd.PersistentFlags().Set("bind_port", "9000"))

	mergeServerConfigFlags(cmd, dst, src)

	require.Equal(t, "127.0.0.1", dst.BindAddr)
	require.Equal(t, 9000, dst.BindPort)
}
