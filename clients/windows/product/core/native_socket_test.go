// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"net"
	"runtime"
	"syscall"
	"testing"
)

type socketUpstream struct{ net.Conn }

func (c socketUpstream) Upstream() any { return c.Conn }

type invalidSocket struct{ net.Conn }

func (invalidSocket) SyscallConn() (syscall.RawConn, error) { return invalidRaw{}, nil }

type invalidRaw struct{}

func (invalidRaw) Control(fn func(uintptr)) error { fn(^uintptr(0)); return nil }
func (invalidRaw) Read(func(uintptr) bool) error  { return errors.New("UNUSED") }
func (invalidRaw) Write(func(uintptr) bool) error { return errors.New("UNUSED") }
func TestOwnedNativeSocketPolicyAndWrapperUnwrap(t *testing.T) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	state, err := tuneNativeSocket(socketUpstream{conn})
	if err != nil {
		t.Fatal(err)
	}
	if state.receiveBefore <= 0 || state.sendBefore <= 0 || state.receiveAfter <= 0 || state.sendAfter <= 0 {
		t.Fatal("missing actual socket observations", state)
	}
	if runtime.GOOS == "windows" && (state.receiveAfter < nativeSocketBufferSize || state.sendAfter < nativeSocketBufferSize) {
		t.Fatal("Windows buffers below WireGuard request", state)
	}
	t.Logf("OWNED_SOCKET_RCVBUF_BEFORE=%d SNDBUF_BEFORE=%d RCVBUF_AFTER=%d SNDBUF_AFTER=%d", state.receiveBefore, state.sendBefore, state.receiveAfter, state.sendAfter)
}
func TestNativeSocketOptionErrorNotErasedBySuccessfulControl(t *testing.T) {
	if _, err := tuneNativeSocket(invalidSocket{}); err == nil {
		t.Fatal("socket option error was erased")
	}
}
