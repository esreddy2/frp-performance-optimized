package legacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestServerIniAndConversionToV1(t *testing.T) {
	require := require.New(t)

	iniContent := []byte(`
[common]
bind_addr = 127.0.0.1
bind_port = 7000
kcp_bind_port = 7001
quic_bind_port = 7002
vhost_http_port = 8080
vhost_https_port = 8443
tcpmux_httpconnect_port = 1337
dashboard_addr = 127.0.0.1
dashboard_port = 7500
dashboard_user = admin
dashboard_pwd = secret
dashboard_tls_mode = false
pprof_enable = true
enable_prometheus = true
token = my-token
authenticate_heartbeats = true
authenticate_new_work_conns = true
allow_ports = 2000-2005,3001
subdomain_host = example.com
max_ports_per_client = 10

[plugin.user-manager]
addr = 127.0.0.1:9000
path = /handler
ops = Login,NewProxy
tlsVerify = true
`)

	srvLegacy, err := UnmarshalServerConfFromIni(iniContent)
	require.NoError(err)
	require.Equal("2000-2005,3001", srvLegacy.AllowPortsStr)
	require.Contains(srvLegacy.HTTPPlugins, "user-manager")

	v1Srv := Convert_ServerCommonConf_To_v1(&srvLegacy)
	require.Equal("127.0.0.1", v1Srv.BindAddr)
	require.Equal(7000, v1Srv.BindPort)
	require.Equal(7001, v1Srv.KCPBindPort)
	require.Equal(7002, v1Srv.QUICBindPort)
	require.Equal(8080, v1Srv.VhostHTTPPort)
	require.Equal(8443, v1Srv.VhostHTTPSPort)
	require.Equal(1337, v1Srv.TCPMuxHTTPConnectPort)
	// Verify PprofEnable is preserved even when DashboardTLSMode is false
	require.Nil(v1Srv.WebServer.TLS)
	require.True(v1Srv.WebServer.PprofEnable)
	require.True(v1Srv.EnablePrometheus)
	require.ElementsMatch([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, v1Srv.Auth.AdditionalScopes)
	require.Len(v1Srv.AllowPorts, 2)
	require.Len(v1Srv.HTTPPlugins, 1)
	require.Equal("user-manager", v1Srv.HTTPPlugins[0].Name)

	// Also verify DashboardTLSMode = true populates WebServer.TLS
	srvLegacy.DashboardTLSMode = true
	srvLegacy.DashboardTLSCertFile = "/path/cert.pem"
	srvLegacy.DashboardTLSKeyFile = "/path/key.pem"
	v1SrvTLS := Convert_ServerCommonConf_To_v1(&srvLegacy)
	require.NotNil(v1SrvTLS.WebServer.TLS)
	require.Equal("/path/cert.pem", v1SrvTLS.WebServer.TLS.CertFile)
	require.Equal("/path/key.pem", v1SrvTLS.WebServer.TLS.KeyFile)
	require.True(v1SrvTLS.WebServer.PprofEnable)
}

func TestParseClientConfigAndConvertAllTypesToV1(t *testing.T) {
	require := require.New(t)

	tmpDir := t.TempDir()
	incFile := filepath.Join(tmpDir, "inc.ini")
	mainFile := filepath.Join(tmpDir, "frpc.ini")

	incContent := `
[p_stcp]
type = stcp
local_ip = 127.0.0.1
local_port = 22
sk = stcp-sk
allow_users = u1,u2

[p_sudp]
type = sudp
local_ip = 127.0.0.1
local_port = 53
sk = sudp-sk

[p_xtcp]
type = xtcp
local_ip = 127.0.0.1
local_port = 2222
sk = xtcp-sk

[v_stcp]
role = visitor
type = stcp
server_name = p_stcp
sk = stcp-sk
bind_addr = 127.0.0.1
bind_port = 6000
use_encryption = true
use_compression = true

[v_sudp]
role = visitor
type = sudp
server_name = p_sudp
sk = sudp-sk
bind_port = 6001

[v_xtcp]
role = visitor
type = xtcp
server_name = p_xtcp
sk = xtcp-sk
bind_port = 6002
protocol = kcp
keep_tunnel_open = true
fallback_to = v_stcp
fallback_timeout_ms = 500
`
	require.NoError(os.WriteFile(incFile, []byte(incContent), 0o600))

	mainContent := `
[common]
user = alice
server_addr = 127.0.0.1
server_port = 7000
protocol = kcp
token = secret
authenticate_heartbeats = true
authenticate_new_work_conns = true
admin_addr = 127.0.0.1
admin_port = 7400
meta_env = prod
includes = ` + incFile + `

[p_tcp]
type = tcp
local_ip = 127.0.0.1
local_port = 8000
remote_port = 9000
use_encryption = true
use_compression = true
bandwidth_limit = 1MB
bandwidth_limit_mode = server
proxy_protocol_version = v2
group = g1
group_key = gk1
health_check_type = tcp
health_check_timeout_s = 3
health_check_max_failed = 2
health_check_interval_s = 10
meta_role = web

[p_udp]
type = udp
local_ip = 127.0.0.1
local_port = 8001
remote_port = 9001

[p_http]
type = http
local_port = 8080
custom_domains = a.example.com
subdomain = sub
locations = /api,/v1
http_user = u
http_pwd = p
host_header_rewrite = internal.local
header_X-From = frp
route_by_http_user = u
health_check_type = http
health_check_url = /healthz

[p_https]
type = https
custom_domains = sec.example.com
plugin = https2http
plugin_local_addr = 127.0.0.1:8080
plugin_host_header_rewrite = localhost
plugin_crt_path = /tmp/c.crt
plugin_key_path = /tmp/c.key
plugin_header_X-Test = val

[p_tcpmux]
type = tcpmux
multiplexer = httpconnect
custom_domains = mux.example.com
http_user = mu
http_pwd = mp
route_by_http_user = mu
local_port = 8090
`
	require.NoError(os.WriteFile(mainFile, []byte(mainContent), 0o600))

	commonLegacy, proxyMap, visitorMap, err := ParseClientConfig(mainFile)
	require.NoError(err)

	v1Common := Convert_ClientCommonConf_To_v1(&commonLegacy)
	require.Equal("alice", v1Common.User)
	require.Equal("127.0.0.1", v1Common.ServerAddr)
	require.Equal(7000, v1Common.ServerPort)
	require.Equal("kcp", v1Common.Transport.Protocol)
	require.Equal("prod", v1Common.Metadatas["env"])
	require.ElementsMatch([]v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}, v1Common.Auth.AdditionalScopes)

	// Convert all 8 proxy types
	require.Len(proxyMap, 8)
	for _, p := range proxyMap {
		v1Proxy := Convert_ProxyConf_To_v1(p)
		require.NotNil(v1Proxy)
		require.NotEmpty(v1Proxy.GetBaseConfig().Name)
	}

	// Verify plugin conversions for remaining plugin types
	pluginTypes := []struct {
		plugin string
		params map[string]string
	}{
		{"http2https", map[string]string{"plugin_local_addr": "127.0.0.1:443", "plugin_header_H": "V"}},
		{"http_proxy", map[string]string{"plugin_http_user": "u", "plugin_http_passwd": "p"}},
		{"https2https", map[string]string{"plugin_local_addr": "127.0.0.1:443", "plugin_crt_path": "c", "plugin_key_path": "k"}},
		{"socks5", map[string]string{"plugin_user": "u", "plugin_passwd": "p"}},
		{"static_file", map[string]string{"plugin_local_path": "/srv", "plugin_strip_prefix": "s"}},
		{"unix_domain_socket", map[string]string{"plugin_unix_path": "/tmp/s.sock"}},
	}
	for _, pt := range pluginTypes {
		tc := &TCPProxyConf{
			BaseProxyConf: BaseProxyConf{
				ProxyName: "plug-" + pt.plugin,
				ProxyType: "tcp",
				LocalSvrConf: LocalSvrConf{
					Plugin:       pt.plugin,
					PluginParams: pt.params,
				},
			},
		}
		v1P := Convert_ProxyConf_To_v1(tc)
		require.Equal(pt.plugin, v1P.GetBaseConfig().Plugin.Type)
		require.NotNil(v1P.GetBaseConfig().Plugin.ClientPluginOptions)
	}

	// Convert all 3 visitor types
	require.Len(visitorMap, 3)
	for _, v := range visitorMap {
		v1Vis := Convert_VisitorConf_To_v1(v)
		require.NotNil(v1Vis)
		require.NotEmpty(v1Vis.GetBaseConfig().Name)
	}
}
