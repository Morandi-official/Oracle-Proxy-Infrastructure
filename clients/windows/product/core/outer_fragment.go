// SPDX-License-Identifier: GPL-3.0-or-later
package main

// IPv6 requires inner MTU >=1280. Permit fragmentation of the encrypted IPv4
// outer datagram on smaller physical links; IPv6 inner packets stay intact.
// All callers except an explicitly dual-stack native carrier retain the old
// default. This does not permit physical application traffic around the guard.
func outerFragment(value []bool) *bool {
	allow := len(value) == 1 && value[0]
	return &allow
}
