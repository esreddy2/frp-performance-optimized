//go:build !linux

package client

import (
	"net"
)

func applyTCPSendQueueOpts(conn *net.TCPConn, notSentLowat, sendBuffer int64) error {
	if sendBuffer > 0 {
		if err := conn.SetWriteBuffer(int(sendBuffer)); err != nil {
			return err
		}
	}
	return nil
}
