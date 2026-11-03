//go:build linux

package client

import (
	"net"

	"golang.org/x/sys/unix"
)

func applyTCPSendQueueOpts(conn *net.TCPConn, notSentLowat, sendBuffer int64) error {
	if sendBuffer > 0 {
		if err := conn.SetWriteBuffer(int(sendBuffer)); err != nil {
			return err
		}
	}
	if notSentLowat > 0 {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return err
		}
		var sockErr error
		if err := rawConn.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, int(notSentLowat))
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return sockErr
		}
	}
	return nil
}
