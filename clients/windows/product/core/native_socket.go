// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"errors"
	"net"
	"syscall"
)

// Match wireguard-go/conn's standard socket policy on this owned UDP socket.
// The OS may clamp the request. Never change global socket limits or sysctls.
const nativeSocketBufferSize = 7 << 20

type nativeSocketBufferState struct{ receiveBefore, sendBefore, receiveAfter, sendAfter int }

func nativeSocketRaw(c net.Conn) (syscall.RawConn, error) {
	var value any = c
	for depth := 0; depth < 8; depth++ {
		if socket, ok := value.(syscall.Conn); ok {
			return socket.SyscallConn()
		}
		upstream, ok := value.(interface{ Upstream() any })
		if !ok {
			break
		}
		value = upstream.Upstream()
	}
	return nil, errors.New("NATIVE_SOCKET_OPTIONS_UNAVAILABLE")
}
func tuneNativeSocket(c net.Conn) (nativeSocketBufferState, error) {
	var state nativeSocketBufferState
	raw, err := nativeSocketRaw(c)
	if err != nil {
		return state, err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		state.receiveBefore, _ = nativeBufferGet(fd, true)
		state.sendBefore, _ = nativeBufferGet(fd, false)
		receiveErr := nativeBufferSet(fd, true, nativeSocketBufferSize)
		sendErr := nativeBufferSet(fd, false, nativeSocketBufferSize)
		state.receiveAfter, _ = nativeBufferGet(fd, true)
		state.sendAfter, _ = nativeBufferGet(fd, false)
		optionErr = errors.Join(receiveErr, sendErr)
	})
	return state, errors.Join(controlErr, optionErr)
}
