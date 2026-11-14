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

package transport

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func newCustomTLSKeyPair(certfile, keyfile string) (*tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func newRandomTLSKeyPair() (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Generate a random positive serial number with 128 bits of entropy.
	// RFC 5280 requires serial numbers to be positive integers (not zero).
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	// Ensure serial number is positive (not zero)
	if serialNumber.Sign() == 0 {
		serialNumber = big.NewInt(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "frp"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour * 10),
		DNSNames:     []string{"localhost", "frp"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&key.PublicKey,
		key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

// Only support one ca file to add
func newCertPool(caPath string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if err := appendCertsFromFile(pool, caPath); err != nil {
		return nil, err
	}
	return pool, nil
}

func appendCertsFromFile(pool *x509.CertPool, caPath string) error {
	caCrt, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}

	if !pool.AppendCertsFromPEM(caCrt) {
		return fmt.Errorf("failed to parse CA certificate from file %q: no valid PEM certificates found", caPath)
	}

	return nil
}

func NewServerTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if certPath == "" || keyPath == "" {
		// server will generate tls conf by itself
		cert, err := newRandomTLSKeyPair()
		if err != nil {
			return nil, err
		}
		base.Certificates = []tls.Certificate{*cert}
	} else {
		cert, err := newCustomTLSKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		base.Certificates = []tls.Certificate{*cert}
	}

	if caPath != "" {
		pool, err := newCertPool(caPath)
		if err != nil {
			return nil, err
		}

		base.ClientAuth = tls.RequireAndVerifyClientCert
		base.ClientCAs = pool
	}

	return base, nil
}

// NewClientTLSConfig builds a client TLS config using only caPath as a trust
// anchor. When caPath is empty, server certificate verification is disabled
// NewClientTLSConfig builds a client TLS config. When no custom CA is provided (caPath == ""),
// it defaults to validating against system CAs (useSystemCa = true), avoiding InsecureSkipVerify by default.
func NewClientTLSConfig(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	return NewClientTLSConfigWithSystemCA(certPath, keyPath, caPath, serverName, caPath == "")
}

// NewClientTLSConfigWithSystemCA enables verification against system CAs when
// useSystemCa is true, adding certificates from caPath if it is also set.
// Without either trust source, server certificate verification remains disabled.
func NewClientTLSConfigWithSystemCA(certPath, keyPath, caPath, serverName string, useSystemCa bool) (*tls.Config, error) {
	return newClientTLSConfig(certPath, keyPath, caPath, serverName, useSystemCa, x509.SystemCertPool)
}

func newClientTLSConfig(
	certPath, keyPath, caPath, serverName string,
	useSystemCa bool,
	systemCertPool func() (*x509.CertPool, error),
) (*tls.Config, error) {
	if (certPath == "") != (keyPath == "") {
		return nil, fmt.Errorf("both tls cert and key must be provided together")
	}

	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if certPath != "" && keyPath != "" {
		cert, err := newCustomTLSKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}

		base.Certificates = []tls.Certificate{*cert}
	}

	base.ServerName = serverName

	switch {
	case caPath != "" && useSystemCa:
		pool, err := systemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to load system CA pool: %w", err)
		}
		if pool == nil {
			return nil, fmt.Errorf("failed to load system CA pool: no pool returned")
		}
		if err := appendCertsFromFile(pool, caPath); err != nil {
			return nil, err
		}
		base.RootCAs = pool
		base.InsecureSkipVerify = false
	case caPath != "":
		pool, err := newCertPool(caPath)
		if err != nil {
			return nil, err
		}

		base.RootCAs = pool
		base.InsecureSkipVerify = false
	case useSystemCa:
		base.InsecureSkipVerify = false
	default:
		// lgtm[go/disabled-certificate-check]
		base.InsecureSkipVerify = true
	}

	return base, nil
}

func NewRandomPrivateKey() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return keyPEM, nil
}
