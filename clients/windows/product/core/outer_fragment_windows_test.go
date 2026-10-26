//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"context"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/windows"
	"syscall"
	"testing"
)

func TestNativeIPv6CarrierUsesRealWindowsOuterFragmentPolicy(t *testing.T) {
	for _, allow := range []bool{false, true} {
		dialer, err := physicalDialer(context.Background(), allow)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := dialer.DialContext(context.Background(), "udp", M.ParseSocksaddr("127.0.0.1:9"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := conn.(syscall.Conn).SyscallConn()
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		var observed int
		var socketErr error
		err = raw.Control(func(fd uintptr) {
			observed, socketErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 71)
		})
		conn.Close()
		if err != nil || socketErr != nil {
			t.Fatalf("query policy: %v %v", err, socketErr)
		}
		expected := 1 // IP_PMTUDISC_DO: preserve current IPv4-only default.
		if allow {
			expected = 2
		} // IP_PMTUDISC_DONT: allow encrypted outer fragmentation.
		if observed != expected {
			t.Fatalf("allow=%v policy=%d want=%d", allow, observed, expected)
		}
	}
}
