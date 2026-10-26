// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "testing"

func TestFixedIngressAllowlist(t *testing.T) {
	for _, address := range []string{"", "152.67.156.100", "141.147.78.44"} {
		got, err := ingressAddress(address)
		if err != nil || got == "" {
			t.Fatal("valid fixed ingress rejected")
		}
	}
	for _, address := range []string{"127.0.0.1", "141.147.78.44:443", "141.147.78.44.evil", "example.org", "::1", " 141.147.78.44"} {
		if _, err := ingressAddress(address); err == nil {
			t.Fatal("unapproved ingress accepted")
		}
	}
}
