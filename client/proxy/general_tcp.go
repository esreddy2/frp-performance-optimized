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

package proxy

import (
	"net"
	"reflect"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

func init() {
	pxyConfs := []v1.ProxyConfigurer{
		&v1.TCPProxyConfig{},
		&v1.HTTPProxyConfig{},
		&v1.HTTPSProxyConfig{},
		&v1.TCPMuxProxyConfig{},
	}
	for _, cfg := range pxyConfs {
		RegisterProxyFactory(reflect.TypeOf(cfg), NewGeneralTCPProxy)
	}
	RegisterProxyFactory(reflect.TypeFor[*v1.STCPProxyConfig](), NewSTCPProxy)
}

// GeneralTCPProxy is a general implementation of Proxy interface for TCP protocol.
// If the default GeneralTCPProxy cannot meet the requirements, you can customize
// the implementation of the Proxy interface.
type GeneralTCPProxy struct {
	*BaseProxy
}

func NewGeneralTCPProxy(baseProxy *BaseProxy, _ v1.ProxyConfigurer) Proxy {
	return &GeneralTCPProxy{
		BaseProxy: baseProxy,
	}
}

// STCPProxy handles work connections for STCP proxies using the proxy's
// configured Secretkey rather than the client's global authentication token.
type STCPProxy struct {
	*BaseProxy

	cfg *v1.STCPProxyConfig
}

func NewSTCPProxy(baseProxy *BaseProxy, cfg v1.ProxyConfigurer) Proxy {
	unwrapped, ok := cfg.(*v1.STCPProxyConfig)
	if !ok {
		return nil
	}
	return &STCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *STCPProxy) InWorkConn(conn net.Conn, m *msg.StartWorkConn) {
	pxy.mu.RLock()
	cb := pxy.inWorkConnCallback
	pxy.mu.RUnlock()
	if cb != nil {
		if !cb(pxy.baseCfg, conn, m) {
			return
		}
	}
	pxy.HandleTCPWorkConnection(conn, m, pxy.encryptionKey)
}
