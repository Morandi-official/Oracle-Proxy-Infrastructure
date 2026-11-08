// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "testing"

func TestAuthenticatedPublicIngress(t *testing.T) {
	for _, address := range []string{"", "152.67.156.100", "141.147.78.44", "152.67.154.225", "150.230.113.158"} {
		got, err := ingressAddress(address)
		if err != nil || got == "" {
			t.Fatal("valid fixed ingress rejected")
		}
	}
	for _, address := range []string{"127.0.0.1", "10.0.0.6", "100.64.0.1", "192.0.2.1", "203.0.113.1", "141.147.78.44:443", "141.147.78.44.evil", "example.org", "::1", " 141.147.78.44"} {
		if _, err := ingressAddress(address); err == nil {
			t.Fatal("unapproved ingress accepted")
		}
	}
}
