//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
//
package main

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
)

func physicalDialer(ctx context.Context) (N.Dialer, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	// --check parses configurations without starting sockets as an ordinary user.
	if user.User.Sid.String() != "S-1-5-18" {
		return dialer.NewDefault(ctx, option.DialerOptions{})
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, e
	}
	dll, e := windows.LoadDLL(filepath.Join(filepath.Dir(executable), "OracleProxy.Guard.dll"))
	if e != nil {
		return nil, e
	}
	defer dll.Release()
	fn, e := dll.FindProc("OpPhysicalIPv4Index")
	if e != nil {
		return nil, e
	}
	index, _, _ := fn.Call()
	if index == 0 {
		return nil, errors.New("PHYSICAL_ROUTE_UNAVAILABLE")
	}
	nic, e := net.InterfaceByIndex(int(index))
	if e != nil {
		return nil, e
	}
	return dialer.NewDefault(ctx, option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{BindInterface: nic.Name}})
}
