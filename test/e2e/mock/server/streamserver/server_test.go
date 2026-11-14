package streamserver

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/test/e2e/pkg/rpc"
)

func TestStreamServerConnectionTrackingAndGracefulClose(t *testing.T) {
	s := New(TCP, WithBindPort(0))
	err := s.Run()
	require.NoError(t, err)

	addr := s.l.Addr().String()

	// Connect a client
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)

	// Send RPC echo request
	testPayload := []byte("hello stream server")
	_, err = rpc.WriteBytes(conn, testPayload)
	require.NoError(t, err)

	resp, err := rpc.ReadBytes(conn)
	require.NoError(t, err)
	require.Equal(t, testPayload, resp)

	// Verify connection is tracked
	s.connsMu.Lock()
	require.Equal(t, 1, len(s.conns))
	s.connsMu.Unlock()

	// Close server. It must close active connections and wait for goroutines to exit.
	closeDone := make(chan struct{})
	go func() {
		defer close(closeDone)
		_ = s.Close()
	}()

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("s.Close() did not complete in time")
	}

	// Verify conns map is empty
	s.connsMu.Lock()
	require.Equal(t, 0, len(s.conns))
	require.True(t, s.closed)
	s.connsMu.Unlock()

	// Reading from client connection should now fail (server closed it)
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Read(make([]byte, 10))
	require.Error(t, err)
	_ = conn.Close()
}

func TestStreamServerUDPAndCustomHandler(t *testing.T) {
	// Verify WithRespContent option
	fixedContent := []byte("fixed response")
	s := New(TCP, WithBindPort(0), WithRespContent(fixedContent))
	require.NoError(t, s.Run())
	defer s.Close()

	addr := s.l.Addr().String()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	_, err = rpc.WriteBytes(conn, []byte("ignored request"))
	require.NoError(t, err)

	resp, err := rpc.ReadBytes(conn)
	require.NoError(t, err)
	require.Equal(t, fixedContent, resp)
}

func TestStreamServerBindAddrAndPort(t *testing.T) {
	s := New(TCP, WithBindAddr("127.0.0.1"), WithBindPort(12345))
	require.Equal(t, "127.0.0.1", s.BindAddr())
	require.Equal(t, 12345, s.BindPort())
	require.Equal(t, "12345", strconv.Itoa(s.BindPort()))
}
