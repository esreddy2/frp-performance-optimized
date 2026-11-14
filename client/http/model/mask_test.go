package model

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// TestProxyAndVisitorDefinitionMasking_CANON066 verifies that sensitive credentials
// are masked with "******" in response models while leaving the original in-memory configs untouched.
//
//nolint:gosec // test-only credentials
func TestProxyAndVisitorDefinitionMasking_CANON066(t *testing.T) {
	require := require.New(t)

	// 1. STCP Proxy
	stcpOriginal := &v1.STCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "stcp-p", Type: "stcp"},
		Secretkey:       "my-stcp-secret-123", //nolint:gosec // test-only secret
	}
	pDef, err := ProxyDefinitionFromConfigurer(stcpOriginal)
	require.NoError(err)
	require.Equal(MaskedSecret, pDef.STCP.Secretkey, "STCP Secretkey must be masked")
	require.Equal("my-stcp-secret-123", stcpOriginal.Secretkey, "original STCP config must not be mutated")

	// 2. SUDP Proxy
	sudpOriginal := &v1.SUDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "sudp-p", Type: "sudp"},
		Secretkey:       "my-sudp-secret-456", //nolint:gosec // test-only secret
	}
	pDef, err = ProxyDefinitionFromConfigurer(sudpOriginal)
	require.NoError(err)
	require.Equal(MaskedSecret, pDef.SUDP.Secretkey, "SUDP Secretkey must be masked")
	require.Equal("my-sudp-secret-456", sudpOriginal.Secretkey, "original SUDP config must not be mutated")

	// 3. XTCP Proxy
	xtcpOriginal := &v1.XTCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "xtcp-p", Type: "xtcp"},
		Secretkey:       "my-xtcp-secret-789", //nolint:gosec // test-only secret
	}
	pDef, err = ProxyDefinitionFromConfigurer(xtcpOriginal)
	require.NoError(err)
	require.Equal(MaskedSecret, pDef.XTCP.Secretkey, "XTCP Secretkey must be masked")
	require.Equal("my-xtcp-secret-789", xtcpOriginal.Secretkey, "original XTCP config must not be mutated")

	// 4. HTTP Proxy with HTTPPassword
	httpOriginal := &v1.HTTPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "http-p", Type: "http"},
		HTTPPassword:    "my-http-password",
	}
	pDef, err = ProxyDefinitionFromConfigurer(httpOriginal)
	require.NoError(err)
	require.Equal(MaskedSecret, pDef.HTTP.HTTPPassword, "HTTP HTTPPassword must be masked")
	require.Equal("my-http-password", httpOriginal.HTTPPassword, "original HTTP config must not be mutated")

	// 5. TCPMux Proxy with HTTPPassword
	tcpmuxOriginal := &v1.TCPMuxProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "tcpmux-p", Type: "tcpmux"},
		HTTPPassword:    "my-tcpmux-password", //nolint:gosec // test-only credential
	}
	pDef, err = ProxyDefinitionFromConfigurer(tcpmuxOriginal)
	require.NoError(err)
	require.Equal(MaskedSecret, pDef.TCPMux.HTTPPassword, "TCPMux HTTPPassword must be masked")
	require.Equal("my-tcpmux-password", tcpmuxOriginal.HTTPPassword, "original TCPMux config must not be mutated")

	// 6. TCP Proxy with Socks5 Plugin password
	socks5Original := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: "socks5-p",
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				Plugin: v1.TypedClientPluginOptions{
					Type: "socks5",
					ClientPluginOptions: &v1.Socks5PluginOptions{
						Password: "socks5-secret-pw", //nolint:gosec // test-only credential
					},
				},
			},
		},
	}
	pDef, err = ProxyDefinitionFromConfigurer(socks5Original)
	require.NoError(err)
	opt := pDef.TCP.Plugin.ClientPluginOptions.(*v1.Socks5PluginOptions)
	require.Equal(MaskedSecret, opt.Password, "Socks5 plugin password must be masked")
	origOpt := socks5Original.Plugin.ClientPluginOptions.(*v1.Socks5PluginOptions)
	require.Equal("socks5-secret-pw", origOpt.Password, "original socks5 config must not be mutated")

	// 7. STCP Visitor
	stcpVisitorOrig := &v1.STCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{Name: "stcp-v", Type: "stcp", SecretKey: "visitor-secret-key-1"},
	}
	vDef, err := VisitorDefinitionFromConfigurer(stcpVisitorOrig)
	require.NoError(err)
	require.Equal(MaskedSecret, vDef.STCP.SecretKey, "STCP Visitor SecretKey must be masked")
	require.Equal("visitor-secret-key-1", stcpVisitorOrig.SecretKey, "original visitor config must not be mutated")

	// 8. SUDP Visitor
	sudpVisitorOrig := &v1.SUDPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{Name: "sudp-v", Type: "sudp", SecretKey: "visitor-secret-key-2"},
	}
	vDef, err = VisitorDefinitionFromConfigurer(sudpVisitorOrig)
	require.NoError(err)
	require.Equal(MaskedSecret, vDef.SUDP.SecretKey, "SUDP Visitor SecretKey must be masked")
	require.Equal("visitor-secret-key-2", sudpVisitorOrig.SecretKey, "original visitor config must not be mutated")

	// 9. XTCP Visitor
	xtcpVisitorOrig := &v1.XTCPVisitorConfig{
		VisitorBaseConfig: v1.VisitorBaseConfig{Name: "xtcp-v", Type: "xtcp", SecretKey: "visitor-secret-key-3"},
	}
	vDef, err = VisitorDefinitionFromConfigurer(xtcpVisitorOrig)
	require.NoError(err)
	require.Equal(MaskedSecret, vDef.XTCP.SecretKey, "XTCP Visitor SecretKey must be masked")
	require.Equal("visitor-secret-key-3", xtcpVisitorOrig.SecretKey, "original visitor config must not be mutated")
}
