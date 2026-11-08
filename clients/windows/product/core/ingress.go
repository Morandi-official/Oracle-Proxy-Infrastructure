// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"net/netip"
)

// Addresses arrive only through the authenticated owner's endpoint catalog.
func ingressAddress(value string) (string, error) {
	if value == "" {
		return "152.67.156.100", nil
	} // legacy logical default, never a DNS bootstrap
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return "", errors.New("INGRESS_ADDRESS_REJECTED")
	}
	for _, prefix := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"} {
		if netip.MustParsePrefix(prefix).Contains(address) {
			return "", errors.New("INGRESS_ADDRESS_REJECTED")
		}
	}
	return value, nil
}
