//go:build !windows

// SPDX-License-Identifier: GPL-3.0-or-later
//
package main

import (
	"context"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func physicalDialer(ctx context.Context) (N.Dialer, error) {
	return dialer.NewDefault(ctx, option.DialerOptions{})
}
