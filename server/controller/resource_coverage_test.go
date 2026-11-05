package controller

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	"github.com/fatedier/frp/pkg/nathole"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/group"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/visitor"
)

type coverageFakeListener struct {
	closeErr error
}

func (f *coverageFakeListener) Accept() (net.Conn, error) { return nil, io.EOF }
func (f *coverageFakeListener) Close() error              { return f.closeErr }
func (f *coverageFakeListener) Addr() net.Addr            { return nil }

func TestResourceControllerCloseInvokesManagersAndPropagatesErrors(t *testing.T) {
	require := require.New(t)

	vhostErr := errors.New("vhost close error")
	tcpmuxErr := errors.New("tcpmux close error")

	vhostListener := &coverageFakeListener{closeErr: vhostErr}
	tcpmuxListener := &coverageFakeListener{closeErr: tcpmuxErr}

	httpsMuxer, err := vhost.NewHTTPSMuxer(vhostListener, time.Second)
	require.NoError(err)
	tcpmuxMuxer, err := tcpmux.NewHTTPConnectTCPMuxer(tcpmuxListener, false, time.Second)
	require.NoError(err)

	portMgr := ports.NewManager("tcp", "127.0.0.1", []types.PortsRange{{Single: 1}})
	udpPortMgr := ports.NewManager("udp", "127.0.0.1", []types.PortsRange{{Single: 1}})

	natholeCtl, err := nathole.NewController(time.Second)
	require.NoError(err)

	rc := &ResourceController{
		TCPPortManager:         portMgr,
		UDPPortManager:         udpPortMgr,
		VhostHTTPSMuxer:        httpsMuxer,
		TCPMuxHTTPConnectMuxer: tcpmuxMuxer,
		VisitorManager:         visitor.NewManager(),
		TCPGroupCtl:            group.NewTCPGroupCtl(portMgr),
		HTTPGroupCtl:           group.NewHTTPGroupController(vhost.NewRouters()),
		HTTPSGroupCtl:          group.NewHTTPSGroupController(httpsMuxer),
		TCPMuxGroupCtl:         group.NewTCPMuxGroupCtl(tcpmuxMuxer),
		NatHoleController:      natholeCtl,
		PluginManager:          plugin.NewManager(),
	}

	err = rc.Close()
	require.Error(err)
	require.ErrorIs(err, vhostErr)
	require.ErrorIs(err, tcpmuxErr)
}
