// SPDX-License-Identifier: GPL-3.0-or-later
package main

func validNativePorts(ports []uint16) bool {
	if len(ports) == 1 {
		return ports[0] != 0 // CI may use one ephemeral loopback endpoint.
	}
	if len(ports) != 2 || ports[0] == ports[1] {
		return false
	}
	return ports[0] == 443 && (ports[1] == 51820 || ports[1] == 8443) ||
		ports[1] == 443 && (ports[0] == 51820 || ports[0] == 8443)
}
