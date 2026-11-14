// Copyright 2025 The frp Authors
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

package vnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

const (
	defaultTunName = "utun"
	defaultMTU     = 1420
)

func openTun(_ context.Context, addr string) (tun.Device, error) {
	ip, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return nil, err
	}

	dev, err := tun.CreateTUN(defaultTunName, defaultMTU)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = dev.Close()
		}
	}()

	name, err := dev.Name()
	if err != nil {
		return nil, err
	}

	// Calculate a peer IP for the point-to-point tunnel
	peerIP := generatePeerIP(ip)
	isIPv6 := ip.To4() == nil

	// Configure the interface with proper point-to-point addressing
	if isIPv6 {
		if err = exec.Command("ifconfig", name, "inet6", ip.String(), peerIP.String(), "mtu", fmt.Sprint(defaultMTU), "up").Run(); err != nil {
			return nil, err
		}
	} else {
		if err = exec.Command("ifconfig", name, "inet", ip.String(), peerIP.String(), "mtu", fmt.Sprint(defaultMTU), "up").Run(); err != nil {
			return nil, err
		}
	}

	// Add default route for the tunnel subnet
	routes := []net.IPNet{*ipNet}
	if err = addRoutes(name, routes); err != nil {
		return nil, err
	}
	cleanup = false
	return dev, nil
}

// generatePeerIP creates a peer IP for the point-to-point tunnel
// using 32-bit integer arithmetic with boundary handling for IPv4
func generatePeerIP(ip net.IP) net.IP {
	if ip4 := ip.To4(); ip4 != nil {
		val := binary.BigEndian.Uint32(ip4)
		if val&0xff == 255 {
			val--
		} else {
			val++
		}
		res := make(net.IP, 4)
		binary.BigEndian.PutUint32(res, val)
		return res
	}

	peerIP := make(net.IP, len(ip))
	copy(peerIP, ip)
	for i := len(peerIP) - 1; i >= 0; i-- {
		peerIP[i]++
		if peerIP[i] != 0 {
			break
		}
	}
	return peerIP
}

// addRoutes configures system routes for the TUN interface
func addRoutes(ifName string, routes []net.IPNet) error {
	for _, route := range routes {
		routeStr := route.String()
		isIPv6 := route.IP.To4() == nil
		var cmd *exec.Cmd
		if isIPv6 {
			cmd = exec.Command("route", "add", "-inet6", "-net", routeStr, "-interface", ifName)
		} else {
			cmd = exec.Command("route", "add", "-net", routeStr, "-interface", ifName)
		}
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
