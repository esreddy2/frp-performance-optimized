package model

import (
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

type unsupportedProxyConfigurer struct {
	v1.TCPProxyConfig
}

type unsupportedVisitorConfigurer struct {
	v1.STCPVisitorConfig
}

func TestProxyDefinitionValidationAndRoundTrip(t *testing.T) {
	require := require.New(t)

	// 1. Validate error cases
	emptyName := ProxyDefinition{Type: "tcp", TCP: &v1.TCPProxyConfig{}}
	require.ErrorContains(emptyName.Validate("", false), "proxy name is required")

	badType := ProxyDefinition{Name: "p1", Type: "invalid", TCP: &v1.TCPProxyConfig{}}
	require.ErrorContains(badType.Validate("", false), "invalid proxy type")
	require.False(IsProxyType("invalid"))

	mismatchPath := ProxyDefinition{Name: "p1", Type: "tcp", TCP: &v1.TCPProxyConfig{}}
	require.ErrorContains(mismatchPath.Validate("p2", true), "proxy name in URL must match")
	require.NoError(mismatchPath.Validate("p2", false))

	noBlock := ProxyDefinition{Name: "p1", Type: "tcp"}
	require.ErrorContains(noBlock.Validate("p1", true), "exactly one proxy type block is required")
	_, err := noBlock.ToConfigurer()
	require.ErrorContains(err, "exactly one proxy type block is required")

	twoBlocks := ProxyDefinition{
		Name: "p1",
		Type: "tcp",
		TCP:  &v1.TCPProxyConfig{},
		UDP:  &v1.UDPProxyConfig{},
	}
	require.ErrorContains(twoBlocks.Validate("p1", true), "exactly one proxy type block is required")
	_, err = twoBlocks.ToConfigurer()
	require.ErrorContains(err, "exactly one proxy type block is required")

	wrongBlock := ProxyDefinition{
		Name: "p1",
		Type: "tcp",
		UDP:  &v1.UDPProxyConfig{},
	}
	require.ErrorContains(wrongBlock.Validate("p1", true), "does not match type")
	_, err = wrongBlock.ToConfigurer()
	require.ErrorContains(err, "does not match type")

	// 2. Round-trip all 8 supported proxy types
	cases := []ProxyDefinition{
		{Name: "p-tcp", Type: "tcp", TCP: &v1.TCPProxyConfig{RemotePort: 6000}},
		{Name: "p-udp", Type: "udp", UDP: &v1.UDPProxyConfig{RemotePort: 6001}},
		{Name: "p-http", Type: "http", HTTP: &v1.HTTPProxyConfig{DomainConfig: v1.DomainConfig{SubDomain: "web"}}},
		{Name: "p-https", Type: "https", HTTPS: &v1.HTTPSProxyConfig{DomainConfig: v1.DomainConfig{SubDomain: "sec"}}},
		{Name: "p-tcpmux", Type: "tcpmux", TCPMux: &v1.TCPMuxProxyConfig{Multiplexer: "httpconnect"}},
		{Name: "p-stcp", Type: "stcp", STCP: &v1.STCPProxyConfig{Secretkey: "sk1"}},
		{Name: "p-sudp", Type: "sudp", SUDP: &v1.SUDPProxyConfig{Secretkey: "sk2"}},
		{Name: "p-xtcp", Type: "xtcp", XTCP: &v1.XTCPProxyConfig{Secretkey: "sk3"}},
	}

	for _, tc := range cases {
		require.True(IsProxyType(tc.Type))
		require.NoError(tc.Validate(tc.Name, true))

		cfg, err := tc.ToConfigurer()
		require.NoError(err)
		require.Equal(tc.Name, cfg.GetBaseConfig().Name)
		require.Equal(tc.Type, cfg.GetBaseConfig().Type)

		back, err := ProxyDefinitionFromConfigurer(cfg)
		require.NoError(err)
		require.Equal(tc.Name, back.Name)
		require.Equal(tc.Type, back.Type)
		require.NoError(back.Validate(tc.Name, true))
	}

	// 3. ProxyDefinitionFromConfigurer error cases
	_, err = ProxyDefinitionFromConfigurer(nil)
	require.ErrorContains(err, "proxy config is nil")

	_, err = ProxyDefinitionFromConfigurer(&unsupportedProxyConfigurer{})
	require.ErrorContains(err, "unsupported proxy configurer type")
}

func TestVisitorDefinitionValidationAndRoundTrip(t *testing.T) {
	require := require.New(t)

	// 1. Validate error cases
	emptyName := VisitorDefinition{Type: "stcp", STCP: &v1.STCPVisitorConfig{}}
	require.ErrorContains(emptyName.Validate("", false), "visitor name is required")

	badType := VisitorDefinition{Name: "v1", Type: "tcp", STCP: &v1.STCPVisitorConfig{}}
	require.ErrorContains(badType.Validate("", false), "invalid visitor type")
	require.False(IsVisitorType("tcp"))

	mismatchPath := VisitorDefinition{Name: "v1", Type: "stcp", STCP: &v1.STCPVisitorConfig{}}
	require.ErrorContains(mismatchPath.Validate("v2", true), "visitor name in URL must match")
	require.NoError(mismatchPath.Validate("v2", false))

	noBlock := VisitorDefinition{Name: "v1", Type: "stcp"}
	require.ErrorContains(noBlock.Validate("v1", true), "exactly one visitor type block is required")
	_, err := noBlock.ToConfigurer()
	require.ErrorContains(err, "exactly one visitor type block is required")

	twoBlocks := VisitorDefinition{
		Name: "v1",
		Type: "stcp",
		STCP: &v1.STCPVisitorConfig{},
		SUDP: &v1.SUDPVisitorConfig{},
	}
	require.ErrorContains(twoBlocks.Validate("v1", true), "exactly one visitor type block is required")
	_, err = twoBlocks.ToConfigurer()
	require.ErrorContains(err, "exactly one visitor type block is required")

	wrongBlock := VisitorDefinition{
		Name: "v1",
		Type: "stcp",
		XTCP: &v1.XTCPVisitorConfig{},
	}
	require.ErrorContains(wrongBlock.Validate("v1", true), "does not match type")
	_, err = wrongBlock.ToConfigurer()
	require.ErrorContains(err, "does not match type")

	// 2. Round-trip all 3 supported visitor types
	cases := []VisitorDefinition{
		{Name: "v-stcp", Type: "stcp", STCP: &v1.STCPVisitorConfig{}},
		{Name: "v-sudp", Type: "sudp", SUDP: &v1.SUDPVisitorConfig{}},
		{Name: "v-xtcp", Type: "xtcp", XTCP: &v1.XTCPVisitorConfig{}},
	}

	for _, tc := range cases {
		require.True(IsVisitorType(tc.Type))
		require.NoError(tc.Validate(tc.Name, true))

		cfg, err := tc.ToConfigurer()
		require.NoError(err)
		require.Equal(tc.Name, cfg.GetBaseConfig().Name)
		require.Equal(tc.Type, cfg.GetBaseConfig().Type)

		back, err := VisitorDefinitionFromConfigurer(cfg)
		require.NoError(err)
		require.Equal(tc.Name, back.Name)
		require.Equal(tc.Type, back.Type)
		require.NoError(back.Validate(tc.Name, true))
	}

	// 3. VisitorDefinitionFromConfigurer error cases
	_, err = VisitorDefinitionFromConfigurer(nil)
	require.ErrorContains(err, "visitor config is nil")

	_, err = VisitorDefinitionFromConfigurer(&unsupportedVisitorConfigurer{})
	require.ErrorContains(err, "unsupported visitor configurer type")
}
