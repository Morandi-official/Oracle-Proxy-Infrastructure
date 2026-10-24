//go:build !windows

// SPDX-License-Identifier: GPL-3.0-or-later
package main

import "syscall"

func nativeBufferOption(receive bool) int {
	if receive {
		return syscall.SO_RCVBUF
	}
	return syscall.SO_SNDBUF
}
func nativeBufferGet(fd uintptr, receive bool) (int, error) {
	return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, nativeBufferOption(receive))
}
func nativeBufferSet(fd uintptr, receive bool, size int) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, nativeBufferOption(receive), size)
}
