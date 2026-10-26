// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "errors"

// Only fixed owner entrances can be selected by authenticated account metadata.
// WireGuard's logical peer and keys are unchanged; HTTPS retains the primary.
func ingressAddress(value string) (string, error) {
	switch value {
	case "", "152.67.156.100":
		return "152.67.156.100", nil
	case "141.147.78.44":
		return value, nil
	default:
		return "", errors.New("INGRESS_ADDRESS_REJECTED")
	}
}
