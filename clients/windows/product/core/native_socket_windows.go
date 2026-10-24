//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "golang.org/x/sys/windows"

func nativeBufferOption(receive bool) int {
	if receive {
		return windows.SO_RCVBUF
	}
	return windows.SO_SNDBUF
}
func nativeBufferGet(fd uintptr, receive bool) (int, error) {
	return windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, nativeBufferOption(receive))
}
func nativeBufferSet(fd uintptr, receive bool, size int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, nativeBufferOption(receive), size)
}
