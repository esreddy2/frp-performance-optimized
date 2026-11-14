package cert

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block, "failed to decode certificate PEM")
	c, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return c
}

func TestSelfSignedCertGeneratorIPv6(t *testing.T) {
	generator := &SelfSignedCertGenerator{}

	// Test IPv6 address
	artifacts, err := generator.Generate("::1")
	require.NoError(t, err)
	require.NotNil(t, artifacts)

	cert := parseCert(t, artifacts.Cert)
	var foundIPv6 bool
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("::1")) {
			foundIPv6 = true
			break
		}
	}
	require.True(t, foundIPv6, "IPv6 address ::1 must be present in IPAddresses SANs")
	require.NotContains(t, cert.DNSNames, "::1", "IPv6 address must not be in DNSNames")

	// Test IPv4 address
	artifactsV4, err := generator.Generate("127.0.0.1")
	require.NoError(t, err)
	certV4 := parseCert(t, artifactsV4.Cert)
	var foundIPv4 bool
	for _, ip := range certV4.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIPv4 = true
			break
		}
	}
	require.True(t, foundIPv4, "IPv4 address 127.0.0.1 must be present in IPAddresses SANs")

	// Test domain name
	artifactsDNS, err := generator.Generate("example.com")
	require.NoError(t, err)
	certDNS := parseCert(t, artifactsDNS.Cert)
	require.Contains(t, certDNS.DNSNames, "example.com")
	require.Empty(t, certDNS.IPAddresses)
}
