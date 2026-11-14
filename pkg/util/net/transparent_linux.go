//go:build linux

package net

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ErrTransparentNotSupported indicates transparent proxying is not supported on this platform.
var ErrTransparentNotSupported = errors.New("transparent proxying is only supported on Linux")

// SetSocketTransparent applies SO_REUSEADDR, SO_REUSEPORT, IP_TRANSPARENT (or IPV6_TRANSPARENT),
// and optionally SO_MARK to a raw socket file descriptor.
func SetSocketTransparent(fd uintptr, isIPv6 bool, socketMark int) error {
	// Enable SO_REUSEADDR and SO_REUSEPORT
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setsockopt SO_REUSEADDR: %w", err)
	}
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("setsockopt SO_REUSEPORT: %w", err)
	}

	// Apply IP_TRANSPARENT
	if isIPv6 {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			return fmt.Errorf("setsockopt IPV6_TRANSPARENT (requires CAP_NET_ADMIN): %w", err)
		}
	} else {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
			return fmt.Errorf("setsockopt IP_TRANSPARENT (requires CAP_NET_ADMIN): %w", err)
		}
	}

	// Apply SO_MARK if requested
	if socketMark > 0 {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, socketMark); err != nil {
			return fmt.Errorf("setsockopt SO_MARK (%d): %w", socketMark, err)
		}
	}
	return nil
}

// isIPv6Address returns true if dstIP is a non-IPv4-mapped IPv6 address,
// or if dstIP is nil and localIP is a non-IPv4-mapped IPv6 address.
func isIPv6Address(localIP, dstIP net.IP) bool {
	if dstIP != nil {
		return dstIP.To4() == nil
	}
	return localIP != nil && localIP.To4() == nil
}

// DialTCPTransparent dials a TCP connection to dstAddr using localAddr as the spoofed source address.
// It sets IP_TRANSPARENT and SO_REUSEADDR/SO_REUSEPORT before binding.
// If dialing with localAddr fails due to port collision (EADDRINUSE), it automatically retries with localAddr.IP:0
// to preserve the client IP with an ephemeral source port.
func DialTCPTransparent(
	ctx context.Context,
	localAddr *net.TCPAddr,
	dstAddr *net.TCPAddr,
	timeout time.Duration,
	socketMark int,
) (net.Conn, error) {
	if dstAddr == nil {
		return nil, errors.New("destination address cannot be nil")
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Timeout:   timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				var localIP net.IP
				if localAddr != nil {
					localIP = localAddr.IP
				}
				ctrlErr = SetSocketTransparent(fd, isIPv6Address(localIP, dstAddr.IP), socketMark)
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", dstAddr.String())
	if err != nil && localAddr != nil && localAddr.Port != 0 && isAddrInUse(err) {
		// Fallback to ephemeral port on port collision
		fallbackAddr := &net.TCPAddr{
			IP:   localAddr.IP,
			Port: 0,
			Zone: localAddr.Zone,
		}
		dialer.LocalAddr = fallbackAddr
		conn, err = dialer.DialContext(ctx, "tcp", dstAddr.String())
	}
	return conn, err
}

// DialUDPTransparent dials a UDP connection to dstAddr using localAddr as the spoofed source address.
// It sets IP_TRANSPARENT and SO_REUSEADDR/SO_REUSEPORT before binding.
// If dialing with localAddr fails due to port collision (EADDRINUSE), it automatically retries with localAddr.IP:0.
func DialUDPTransparent(
	ctx context.Context,
	localAddr *net.UDPAddr,
	dstAddr *net.UDPAddr,
	socketMark int,
) (*net.UDPConn, error) {
	if dstAddr == nil {
		return nil, errors.New("destination address cannot be nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				var localIP net.IP
				if localAddr != nil {
					localIP = localAddr.IP
				}
				ctrlErr = SetSocketTransparent(fd, isIPv6Address(localIP, dstAddr.IP), socketMark)
			})
			if err != nil {
				return err
			}
			return ctrlErr
		},
	}

	c, err := dialer.DialContext(dialCtx, "udp", dstAddr.String())
	if err != nil && localAddr != nil && localAddr.Port != 0 && isAddrInUse(err) {
		fallbackAddr := &net.UDPAddr{
			IP:   localAddr.IP,
			Port: 0,
			Zone: localAddr.Zone,
		}
		dialer.LocalAddr = fallbackAddr
		c, err = dialer.DialContext(dialCtx, "udp", dstAddr.String())
	}
	if err != nil {
		return nil, err
	}

	udpConn, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("dialed conn is not *net.UDPConn: %T", c)
	}
	return udpConn, nil
}

func probeTransparentSocket(isIPv6 bool) error {
	if isIPv6 {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
		if err != nil {
			return fmt.Errorf("IPv6 transparent proxying socket probe failed: %w", err)
		}
		defer unix.Close(fd)
		if optErr := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); optErr != nil {
			if errors.Is(optErr, syscall.EPERM) {
				return fmt.Errorf("IPv6 transparent proxying requires CAP_NET_ADMIN capability: %w", optErr)
			}
			return fmt.Errorf("IPv6 transparent proxying IPV6_TRANSPARENT probe failed: %w", optErr)
		}
		return nil
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("IPv4 transparent proxying socket probe failed: %w", err)
	}
	defer unix.Close(fd)
	if optErr := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1); optErr != nil {
		if errors.Is(optErr, syscall.EPERM) {
			return fmt.Errorf("IPv4 transparent proxying requires CAP_NET_ADMIN capability: %w", optErr)
		}
		return fmt.Errorf("IPv4 transparent proxying IP_TRANSPARENT probe failed: %w", optErr)
	}
	return nil
}

// CheckTransparentSupport checks whether the system supports transparent proxying
// and verifies relevant kernel networking configuration (sysctl) on Linux.
func CheckTransparentSupport(localIP string) ([]string, error) {
	var warnings []string

	parsedIP := net.ParseIP(localIP)
	isIPv6 := parsedIP != nil && parsedIP.To4() == nil

	// 1. Check capability by testing IP_TRANSPARENT / IPV6_TRANSPARENT setsockopt on a dummy socket
	if err := probeTransparentSocket(isIPv6); err != nil {
		return nil, err
	}

	// 2. Check sysctl policies
	if isIPv6 {
		if parsedIP.IsLoopback() {
			if val, readErr := readSysctl("/proc/sys/net/ipv6/conf/all/route_localnet"); readErr == nil && val == "0" {
				warnings = append(warnings, fmt.Sprintf(
					"localIP [%s] is loopback but /proc/sys/net/ipv6/conf/all/route_localnet is disabled (0); "+
						"kernel may drop non-local spoofed packets on loopback", localIP))
			} else if readErr != nil {
				warnings = append(warnings, fmt.Sprintf(
					"localIP [%s] is IPv6 loopback; ensure 'ip -6 rule' and 'ip -6 route add local ::/0 dev lo' "+
						"are configured for transparent return traffic", localIP))
			}
		}
		if val, readErr := readSysctl("/proc/sys/net/ipv6/conf/all/forwarding"); readErr == nil && val == "0" {
			warnings = append(warnings,
				"/proc/sys/net/ipv6/conf/all/forwarding is disabled (0); "+
					"transparent policy routing across interfaces may fail unless 'sysctl -w net.ipv6.conf.all.forwarding=1' is set")
		}
		return warnings, nil
	}

	if parsedIP != nil && parsedIP.IsLoopback() {
		if val, readErr := readSysctl("/proc/sys/net/ipv4/conf/all/route_localnet"); readErr == nil && val == "0" {
			warnings = append(warnings, fmt.Sprintf(
				"localIP [%s] is loopback but /proc/sys/net/ipv4/conf/all/route_localnet is disabled (0); "+
					"kernel will drop non-local spoofed packets on loopback unless "+
					"'sysctl -w net.ipv4.conf.all.route_localnet=1' is set", localIP))
		}
	}

	if val, readErr := readSysctl("/proc/sys/net/ipv4/ip_forward"); readErr == nil && val == "0" {
		warnings = append(warnings,
			"/proc/sys/net/ipv4/ip_forward is disabled (0); "+
				"transparent policy routing across interfaces may fail unless 'sysctl -w net.ipv4.ip_forward=1' is set")
	}

	return warnings, nil
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE)
}

func readSysctl(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
