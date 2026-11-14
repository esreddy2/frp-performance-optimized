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

package controller

import (
	"errors"

	"github.com/fatedier/frp/pkg/nathole"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/group"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/visitor"
)

// All resource managers and controllers
type ResourceController struct {
	// Manage all visitor listeners
	VisitorManager *visitor.Manager

	// TCP Group Controller
	TCPGroupCtl *group.TCPGroupCtl

	// HTTP Group Controller
	HTTPGroupCtl *group.HTTPGroupController

	// HTTPS Group Controller
	HTTPSGroupCtl *group.HTTPSGroupController

	// TCP Mux Group Controller
	TCPMuxGroupCtl *group.TCPMuxGroupCtl

	// Manage all TCP ports
	TCPPortManager *ports.Manager

	// Manage all UDP ports
	UDPPortManager *ports.Manager

	// For HTTP proxies, forwarding HTTP requests
	HTTPReverseProxy *vhost.HTTPReverseProxy

	// For HTTPS proxies, route requests to different clients by hostname and other information
	VhostHTTPSMuxer *vhost.HTTPSMuxer

	// Controller for nat hole connections
	NatHoleController *nathole.Controller

	// TCPMux HTTP CONNECT multiplexer
	TCPMuxHTTPConnectMuxer *tcpmux.HTTPConnectTCPMuxer

	// All server manager plugin
	PluginManager *plugin.Manager
}

func (rc *ResourceController) Close() error {
	var errs []error

	// Close port managers before vhost muxers to avoid port/routing races.
	if rc.TCPPortManager != nil {
		rc.TCPPortManager.Close()
	}
	if rc.UDPPortManager != nil {
		rc.UDPPortManager.Close()
	}

	if rc.VhostHTTPSMuxer != nil {
		if err := rc.VhostHTTPSMuxer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.TCPMuxHTTPConnectMuxer != nil {
		if err := rc.TCPMuxHTTPConnectMuxer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.HTTPReverseProxy != nil {
		rc.HTTPReverseProxy.Close()
	}

	if rc.VisitorManager != nil {
		if err := rc.VisitorManager.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.TCPGroupCtl != nil {
		if err := rc.TCPGroupCtl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.HTTPGroupCtl != nil {
		if err := rc.HTTPGroupCtl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.HTTPSGroupCtl != nil {
		if err := rc.HTTPSGroupCtl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.TCPMuxGroupCtl != nil {
		if err := rc.TCPMuxGroupCtl.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.NatHoleController != nil {
		if err := rc.NatHoleController.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if rc.PluginManager != nil {
		rc.PluginManager.Close()
	}

	return errors.Join(errs...)
}
