package group

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/config/types"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/server/ports"
)

func TestTCPGroupCtlLoadBalancingAndValidation(t *testing.T) {
	require := require.New(t)

	pm := ports.NewManager("tcp", "127.0.0.1", []types.PortsRange{
		{Start: 41000, End: 41100},
	})
	defer pm.Close()

	ctl := NewTCPGroupCtl(pm)
	defer func() { _ = ctl.Close() }()

	// First member in group acquires port and binds listener
	ln1, realPort1, err := ctl.Listen("pxy-1", "web-tcp-group", "secret-key", "127.0.0.1", 0)
	require.NoError(err)
	require.NotZero(realPort1)
	defer ln1.Close()

	// Second member with matching group, key, addr, and requested port shares the listener
	ln2, realPort2, err := ctl.Listen("pxy-2", "web-tcp-group", "secret-key", "127.0.0.1", 0)
	require.NoError(err)
	require.Equal(realPort1, realPort2)
	defer ln2.Close()

	// Mismatched groupKey must fail with ErrGroupAuthFailed
	_, _, err = ctl.Listen("pxy-bad-key", "web-tcp-group", "wrong-key", "127.0.0.1", 0)
	require.ErrorIs(err, ErrGroupAuthFailed)

	// Mismatched port must fail with ErrGroupDifferentPort
	_, _, err = ctl.Listen("pxy-bad-port", "web-tcp-group", "secret-key", "127.0.0.1", 41050)
	require.ErrorIs(err, ErrGroupDifferentPort)

	// Mismatched address must fail with ErrGroupParamsInvalid
	_, _, err = ctl.Listen("pxy-bad-addr", "web-tcp-group", "secret-key", "0.0.0.0", 0)
	require.ErrorIs(err, ErrGroupParamsInvalid)

	// Incoming TCP connections should be distributed across both group members
	acceptedBy := make(chan string, 2)
	go func() {
		c, acceptErr := ln1.Accept()
		if acceptErr == nil {
			_ = c.Close()
			acceptedBy <- "ln1"
		}
	}()
	go func() {
		c, acceptErr := ln2.Accept()
		if acceptErr == nil {
			_ = c.Close()
			acceptedBy <- "ln2"
		}
	}()

	for range 2 {
		conn, dialErr := net.DialTimeout("tcp", ln1.Addr().String(), 2*time.Second)
		require.NoError(dialErr)
		_ = conn.Close()
	}

	seen := make(map[string]bool)
	for range 2 {
		select {
		case who := <-acceptedBy:
			seen[who] = true
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for TCP group listeners to accept connections")
		}
	}
	require.True(seen["ln1"] && seen["ln2"], "expected both group listeners to receive connections, got %v", seen)

	// Closing both listeners should release the group and port so a new group key can reuse the group name
	require.NoError(ln1.Close())
	require.NoError(ln2.Close())

	ln3, realPort3, err := ctl.Listen("pxy-3", "web-tcp-group", "new-secret-key", "127.0.0.1", 0)
	require.NoError(err)
	require.NotZero(realPort3)
	require.NoError(ln3.Close())
}

func TestHTTPGroupControllerRoutingAndLifecycle(t *testing.T) {
	require := require.New(t)

	routers := vhost.NewRouters()
	ctl := NewHTTPGroupController(routers)
	defer func() { _ = ctl.Close() }()

	called := make(map[string]int)
	makeRouteCfg := func(name, domain, location, user string) vhost.RouteConfig {
		return vhost.RouteConfig{
			Domain:          domain,
			Location:        location,
			RouteByHTTPUser: user,
			CreateConnFn: func(remoteAddr string) (net.Conn, error) {
				called[name]++
				c1, c2 := net.Pipe()
				_ = c2.Close()
				return c1, nil
			},
		}
	}

	cfg1 := makeRouteCfg("p1", "app.example.com", "/api", "alice")
	require.NoError(ctl.Register("p1", "http-grp", "k1", cfg1))

	// Duplicate proxy registration in the same group is rejected
	require.ErrorIs(ctl.Register("p1", "http-grp", "k1", cfg1), ErrProxyRepeated)

	// Wrong group key is rejected
	cfg2 := makeRouteCfg("p2", "app.example.com", "/api", "alice")
	require.ErrorIs(ctl.Register("p2", "http-grp", "wrong-key", cfg2), ErrGroupAuthFailed)

	// Mismatched route config (domain, location, or routeByHTTPUser) is rejected
	badDomainCfg := makeRouteCfg("p2", "other.example.com", "/api", "alice")
	require.ErrorIs(ctl.Register("p2", "http-grp", "k1", badDomainCfg), ErrGroupParamsInvalid)

	// Register second valid proxy
	require.NoError(ctl.Register("p2", "http-grp", "k1", cfg2))

	// Verify route exists in vhost routers and exercise round-robin createConn, chooseEndpoint, and createConnByEndpoint
	_, exist := routers.Get("app.example.com", "/api", "alice")
	require.True(exist)

	httpGrp, ok := ctl.get("http-grp")
	require.True(ok)

	for range 4 {
		c, err := httpGrp.createConn("10.0.0.1:12345")
		require.NoError(err)
		_ = c.Close()
	}
	require.Equal(2, called["p1"])
	require.Equal(2, called["p2"])

	ep1, err := httpGrp.chooseEndpoint()
	require.NoError(err)
	ep2, err := httpGrp.chooseEndpoint()
	require.NoError(err)
	require.NotEqual(ep1, ep2)

	c, err := httpGrp.createConnByEndpoint("p1", "10.0.0.1:12345")
	require.NoError(err)
	_ = c.Close()
	require.Equal(3, called["p1"])

	_, err = httpGrp.createConnByEndpoint("non-existent", "10.0.0.1:12345")
	require.Error(err)

	// Unregistering non-existent group is a safe no-op
	ctl.UnRegister("p1", "no-such-group", cfg1)

	// Unregister first proxy: route still exists and routes solely to p2
	ctl.UnRegister("p1", "http-grp", cfg1)
	epRemaining, err := httpGrp.chooseEndpoint()
	require.NoError(err)
	require.Equal("p2", epRemaining)

	// Unregister last proxy: route is removed from vhost router and empty group returns errors
	ctl.UnRegister("p2", "http-grp", cfg2)
	_, exist = routers.Get("app.example.com", "/api", "alice")
	require.False(exist)
	_, err = httpGrp.chooseEndpoint()
	require.Error(err)
	_, err = httpGrp.createConn("10.0.0.1:12345")
	require.Error(err)
}

func TestHTTPSGroupControllerAndTCPMuxGroupCtl(t *testing.T) {
	require := require.New(t)

	// 1. HTTPSGroupController
	httpsRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer httpsRawLn.Close()

	httpsMuxer, err := vhost.NewHTTPSMuxer(httpsRawLn, time.Second)
	require.NoError(err)
	httpsCtl := NewHTTPSGroupController(httpsMuxer)
	defer func() { _ = httpsCtl.Close() }()

	ctx := context.Background()
	routeCfg := vhost.RouteConfig{Domain: "secure.example.com"}

	hLn1, err := httpsCtl.Listen(ctx, "https-grp", "secret", routeCfg)
	require.NoError(err)
	hLn2, err := httpsCtl.Listen(ctx, "https-grp", "secret", routeCfg)
	require.NoError(err)

	_, err = httpsCtl.Listen(ctx, "https-grp", "bad-secret", routeCfg)
	require.ErrorIs(err, ErrGroupAuthFailed)

	_, err = httpsCtl.Listen(ctx, "https-grp", "secret", vhost.RouteConfig{Domain: "other.example.com"})
	require.ErrorIs(err, ErrGroupParamsInvalid)

	require.NoError(hLn1.Close())
	require.NoError(hLn2.Close())

	// 2. TCPMuxGroupCtl
	muxRawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(err)
	defer muxRawLn.Close()

	httpConnectMuxer, err := tcpmux.NewHTTPConnectTCPMuxer(muxRawLn, false, time.Second)
	require.NoError(err)
	tcpMuxCtl := NewTCPMuxGroupCtl(httpConnectMuxer)
	defer func() { _ = tcpMuxCtl.Close() }()

	muxRoute := vhost.RouteConfig{
		Domain:          "mux.example.com",
		RouteByHTTPUser: "u1",
		Username:        "admin",
		Password:        "pw",
	}

	_, err = tcpMuxCtl.Listen(ctx, "invalid-mux", "mux-grp", "secret", muxRoute)
	require.ErrorContains(err, "unknown multiplexer")

	mLn1, err := tcpMuxCtl.Listen(ctx, "httpconnect", "mux-grp", "secret", muxRoute)
	require.NoError(err)
	mLn2, err := tcpMuxCtl.Listen(ctx, "httpconnect", "mux-grp", "secret", muxRoute)
	require.NoError(err)

	_, err = tcpMuxCtl.Listen(ctx, "httpconnect", "mux-grp", "wrong-secret", muxRoute)
	require.ErrorIs(err, ErrGroupAuthFailed)

	badMuxRoute := muxRoute
	badMuxRoute.Password = "different-pw"
	_, err = tcpMuxCtl.Listen(ctx, "httpconnect", "mux-grp", "secret", badMuxRoute)
	require.ErrorIs(err, ErrGroupParamsInvalid)

	require.NoError(mLn1.Close())
	require.NoError(mLn2.Close())
}
