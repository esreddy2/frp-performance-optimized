// Copyright 2019 fatedier, fatedier@gmail.com
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

//go:build !frps

package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func init() {
	Register(v1.PluginHTTPS2HTTPS, NewHTTPS2HTTPSPlugin)
}

type HTTPS2HTTPSPlugin struct {
	opts *v1.HTTPS2HTTPSPluginOptions

	*httpBridgePlugin
}

func NewHTTPS2HTTPSPlugin(_ PluginContext, options v1.ClientPluginOptions) (Plugin, error) {
	opts := options.(*v1.HTTPS2HTTPSPluginOptions)

	p := &HTTPS2HTTPSPlugin{
		opts: opts,
	}

	var tlsConfig *tls.Config
	if opts.TrustedCaFile != "" {
		caCert, err := os.ReadFile(opts.TrustedCaFile)
		if err != nil {
			return nil, fmt.Errorf("read trusted CA file error: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from file %q", opts.TrustedCaFile)
		}
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			RootCAs:            caPool,
			InsecureSkipVerify: false,
		}
		if opts.HostHeaderRewrite != "" {
			host, _, err := net.SplitHostPort(opts.HostHeaderRewrite)
			if err != nil {
				host = opts.HostHeaderRewrite
			}
			tlsConfig.ServerName = host
		}
	} else {
		// By default bridges to local HTTPS backend without verification for backward compatibility (R3).
		// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
		tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	rp := newHTTPBridgeReverseProxy(
		func(r *httputil.ProxyRequest) {
			r.Out.Header["X-Forwarded-For"] = r.In.Header["X-Forwarded-For"]
			r.SetXForwarded()
			req := r.Out
			rewriteHTTPPluginRequest(req, "https", p.opts.LocalAddr, p.opts.HostHeaderRewrite, p.opts.RequestHeaders)
		},
		tr,
	)

	server, err := newHTTPSBridgePluginServer(rp, p.opts.CrtPath, p.opts.KeyPath, opts.EnableHTTP2, true)
	if err != nil {
		return nil, err
	}
	p.httpBridgePlugin = server

	return p, nil
}

func (p *HTTPS2HTTPSPlugin) Name() string {
	return v1.PluginHTTPS2HTTPS
}
