package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

func TestFlagsRegistrationAndCustomFlags(t *testing.T) {
	require := require.New(t)

	// 1. WordSepNormalizeFunc
	require.Equal("bind-addr", string(WordSepNormalizeFunc(nil, "bind_addr")))
	require.Equal("token", string(WordSepNormalizeFunc(nil, "token")))

	// 2. BoolFuncFlag
	trueCalled := false
	falseCalled := false
	bf := &BoolFuncFlag{
		TrueFunc:  func() { trueCalled = true },
		FalseFunc: func() { falseCalled = true },
	}
	require.Equal("bool", bf.Type())
	require.Equal("false", bf.String())
	require.NoError(bf.Set("true"))
	require.True(trueCalled)
	require.Equal("true", bf.String())
	require.NoError(bf.Set("false"))
	require.True(falseCalled)
	require.Equal("false", bf.String())
	require.Error(bf.Set("not-a-bool"))

	// 3. PortsRangeSliceFlag
	var ranges []types.PortsRange
	prf := &PortsRangeSliceFlag{V: &ranges}
	require.Equal("string", prf.Type())
	require.Equal("", (&PortsRangeSliceFlag{}).String())
	require.NoError(prf.Set("2000-2002,3000"))
	require.Len(ranges, 2)
	require.NotEmpty(prf.String())
	require.Error(prf.Set("invalid-range"))

	// 4. BandwidthQuantityFlag
	var bw types.BandwidthQuantity
	bwf := &BandwidthQuantityFlag{V: &bw}
	require.Equal("string", bwf.Type())
	require.NoError(bwf.Set("1MB"))
	require.Equal("1MB", bwf.String())

	// 5. RegisterServerConfigFlags including --dashboard_tls_mode and --allow_ports
	srvCmd := &cobra.Command{Use: "frps"}
	srvCmd.PersistentFlags().SetNormalizeFunc(WordSepNormalizeFunc)
	var srvCfg v1.ServerConfig
	RegisterServerConfigFlags(srvCmd, &srvCfg)
	require.NoError(srvCmd.PersistentFlags().Parse([]string{
		"--bind_port=7100",
		"--dashboard_tls_cert_file=/tmp/cert.pem",
		"--dashboard_tls_key_file=/tmp/key.pem",
		"--dashboard_tls_mode=true",
		"--allow_ports=4000-4005",
	}))
	require.Equal(7100, srvCfg.BindPort)
	require.Empty(srvCfg.WebServer.Password)
	require.NotNil(srvCfg.WebServer.TLS)
	require.Equal("/tmp/cert.pem", srvCfg.WebServer.TLS.CertFile)
	require.Equal("/tmp/key.pem", srvCfg.WebServer.TLS.KeyFile)
	require.Len(srvCfg.AllowPorts, 1)

	// 6. RegisterClientCommonConfigFlags (normal & WithSSHMode)
	cliCmd := &cobra.Command{Use: "frpc"}
	var cliCfg v1.ClientCommonConfig
	RegisterClientCommonConfigFlags(cliCmd, &cliCfg)
	require.NoError(cliCmd.PersistentFlags().Parse([]string{"--server_addr=10.0.0.1", "--user=bob"}))
	require.Equal("10.0.0.1", cliCfg.ServerAddr)
	require.Equal("bob", cliCfg.User)

	sshCmd := &cobra.Command{Use: "ssh"}
	var sshCliCfg v1.ClientCommonConfig
	RegisterClientCommonConfigFlags(sshCmd, &sshCliCfg, WithSSHMode())
	require.Nil(sshCmd.PersistentFlags().Lookup("server_addr"))
	require.NotNil(sshCmd.PersistentFlags().Lookup("user"))

	// 7. RegisterProxyFlags for all 8 proxy types + WithSSHMode
	proxyConfigs := []v1.ProxyConfigurer{
		&v1.TCPProxyConfig{},
		&v1.UDPProxyConfig{},
		&v1.HTTPProxyConfig{},
		&v1.HTTPSProxyConfig{},
		&v1.TCPMuxProxyConfig{},
		&v1.STCPProxyConfig{},
		&v1.SUDPProxyConfig{},
		&v1.XTCPProxyConfig{},
	}
	for _, pc := range proxyConfigs {
		c := &cobra.Command{Use: "proxy"}
		RegisterProxyFlags(c, pc)
		require.NotNil(c.Flags().Lookup("proxy_name"))
	}
	sshProxyCmd := &cobra.Command{Use: "ssh-proxy"}
	RegisterProxyFlags(sshProxyCmd, &v1.TCPProxyConfig{}, WithSSHMode())
	require.Nil(sshProxyCmd.Flags().Lookup("local_ip"))

	// 8. RegisterVisitorFlags
	visCmd := &cobra.Command{Use: "visitor"}
	var visCfg v1.STCPVisitorConfig
	RegisterVisitorFlags(visCmd, &visCfg)
	require.NoError(visCmd.Flags().Parse([]string{"--visitor_name=v1", "--sk=secret", "--bind_port=6000"}))
	require.Equal("v1", visCfg.Name)
	require.Equal("secret", visCfg.SecretKey)
	require.Equal(6000, visCfg.BindPort)
}

func TestLoadServerAndClientConfigsAndFromMsg(t *testing.T) {
	require := require.New(t)

	// 1. NewProxyConfigurerFromMsg
	srvCfg := &v1.ServerConfig{}
	require.NoError(srvCfg.Complete())

	cfg, err := NewProxyConfigurerFromMsg(&msg.NewProxy{
		ProxyName:  "tcp-from-msg",
		ProxyType:  "tcp",
		RemotePort: 6000,
	}, srvCfg)
	require.NoError(err)
	require.Equal("tcp-from-msg", cfg.GetBaseConfig().Name)

	_, err = NewProxyConfigurerFromMsg(&msg.NewProxy{
		ProxyName: "bad-type",
		ProxyType: "unknown",
	}, srvCfg)
	require.ErrorContains(err, "unknown proxy type")

	// 2. LoadServerConfig (TOML and Legacy INI)
	tmpDir := t.TempDir()
	srvTOML := filepath.Join(tmpDir, "frps.toml")
	require.NoError(os.WriteFile(srvTOML, []byte(`bindPort = 7000`), 0o600))
	loadedSrv, isLegacy, err := LoadServerConfig(srvTOML, true)
	require.NoError(err)
	require.False(isLegacy)
	require.Equal(7000, loadedSrv.BindPort)

	srvINI := filepath.Join(tmpDir, "frps.ini")
	require.NoError(os.WriteFile(srvINI, []byte("[common]\nbind_port = 7001\n"), 0o600))
	loadedLegacySrv, isLegacy, err := LoadServerConfig(srvINI, true)
	require.NoError(err)
	require.True(isLegacy)
	require.Equal(7001, loadedLegacySrv.BindPort)

	// 3. LoadClientConfig with IncludeConfigFiles and Legacy INI
	incDir := filepath.Join(tmpDir, "confd")
	require.NoError(os.MkdirAll(incDir, 0o755))
	incTOML := filepath.Join(incDir, "extra.toml")
	require.NoError(os.WriteFile(incTOML, []byte(`
[[proxies]]
name = "inc-tcp"
type = "tcp"
localPort = 8080
remotePort = 9080

[[visitors]]
name = "inc-stcp"
type = "stcp"
serverName = "srv"
secretKey = "sk"
bindPort = 6001
`), 0o600))

	cliTOML := filepath.Join(tmpDir, "frpc.toml")
	require.NoError(os.WriteFile(cliTOML, []byte(`
user = "alice"
serverAddr = "127.0.0.1"
serverPort = 7000
includes = ["`+filepath.Join(incDir, "*.toml")+`"]

[[proxies]]
name = "main-tcp"
type = "tcp"
localPort = 8000
remotePort = 9000
`), 0o600))

	common, proxies, visitors, isLegacy, err := LoadClientConfig(cliTOML, true)
	require.NoError(err)
	require.False(isLegacy)
	require.Equal("alice", common.User)
	require.Len(proxies, 2)
	require.Len(visitors, 1)

	cliINI := filepath.Join(tmpDir, "frpc.ini")
	require.NoError(os.WriteFile(cliINI, []byte(`
[common]
server_addr = 127.0.0.1
server_port = 7000

[ssh]
type = tcp
local_port = 22
remote_port = 6000

[v1]
role = visitor
type = stcp
server_name = ssh_stcp
sk = 123
bind_port = 6002
`), 0o600))

	_, iniProxies, iniVisitors, isLegacy, err := LoadClientConfig(cliINI, true)
	require.NoError(err)
	require.True(isLegacy)
	require.Len(iniProxies, 1)
	require.Len(iniVisitors, 1)
}
