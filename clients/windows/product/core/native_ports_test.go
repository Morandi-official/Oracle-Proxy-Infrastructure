// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "testing"

func TestNativePortPlansRejectDuplicatesAndUnreviewedPairs(t *testing.T) {
	for _, ports := range [][]uint16{{443, 8443}, {8443, 443}, {51820, 443}, {443, 51820}, {8443}, {443}, {51820}, {32145}} {
		if !validNativePorts(ports) {
			t.Fatalf("valid plan rejected: %v", ports)
		}
	}
	for _, ports := range [][]uint16{nil, {}, {0}, {443, 443}, {8443, 8443}, {443, 0}, {51820, 8443}, {443, 53}, {443, 8443, 51820}} {
		if validNativePorts(ports) {
			t.Fatalf("unreviewed plan accepted: %v", ports)
		}
	}
}
