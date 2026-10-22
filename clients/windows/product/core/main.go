//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Private child of OracleProxyService. Configuration stays in a pipe, never a
// plaintext file or command line. EOF requests graceful route/DNS cleanup.
package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/sagernet/sing-box/adapter"
	oracleTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"io"
	"os"
	"strings"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"golang.org/x/sys/windows"
)

func run() error {
	check := len(os.Args) == 2 && os.Args[1] == "--check"
	standby := len(os.Args) == 2 && os.Args[1] == "--standby"
	if !check && !standby && len(os.Args) != 1 {
		return fmt.Errorf("arguments")
	}
	if !check {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user.User.Sid.String() != "S-1-5-18" {
			return fmt.Errorf("identity")
		}
	}
	defer oracleTun.ClosePreparedOracleAdapter()
	input := bufio.NewReaderSize(os.Stdin, 65536)
	line, err := input.ReadSlice('\n')
	if err != nil || len(line) > 65536 {
		return fmt.Errorf("frame")
	}
	registry := include.OutboundRegistry()
	outbound.Register[relayOptions](registry, relayType, newRelayOutbound)
	outbound.Register[quicOptions](registry, quicType, newQUICOutbound)
	ctx := box.Context(context.Background(), include.InboundRegistry(), registry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	ctx = pause.WithDefaultManager(service.ContextWithDefaultRegistry(ctx))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, line)
	for i := range line {
		line[i] = 0
	}
	if err != nil {
		return fmt.Errorf("configuration")
	}
	var tun option.Inbound
	if standby {
		inbounds := options.Inbounds[:0]
		for _, inbound := range options.Inbounds {
			if inbound.Type == "tun" {
				if tun.Type != "" || inbound.Tag != "device" {
					return fmt.Errorf("configuration")
				}
				tun = inbound
			} else {
				inbounds = append(inbounds, inbound)
			}
		}
		if tun.Type == "" {
			return fmt.Errorf("configuration")
		}
		options.Inbounds = inbounds
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return fmt.Errorf("create")
	}
	if check {
		fmt.Println("CONFIG_VALID")
		return nil
	}
	if err = instance.Start(); err != nil {
		return fmt.Errorf("start")
	}
	fmt.Println("READY")
	var tunScope *adapter.Scope
	if standby {
		// This pipe is inherited only by the authenticated SYSTEM parent. These
		// two fixed operations cannot select programs, routes or destinations.
		for {
			frame, readErr := input.ReadSlice('\n')
			if readErr != nil || len(frame) > 16 {
				break
			}
			switch strings.TrimSuffix(strings.TrimSuffix(string(frame), "\n"), "\r") {
			case "ACTIVATE":
				if tunScope != nil {
					fmt.Println("TUN_ACTIVE")
					continue
				}
				logger := instance.LogFactory().NewLogger("standby-tun")
				entry, createErr := include.InboundRegistry().Create(ctx, instance.Router(), logger, tun.Tag, tun.Type, tun.Options)
				if createErr != nil {
					instance.Close()
					return fmt.Errorf("start")
				}
				lifecycle, ok := entry.(adapter.Lifecycle)
				if !ok {
					instance.Close()
					return fmt.Errorf("start")
				}
				tunScope = adapter.NewScope(ctx, logger)
				for _, stage := range adapter.ListStartStages {
					if startErr := tunScope.Start("device", lifecycle, stage); startErr != nil {
						tunScope.Close()
						instance.Close()
						return fmt.Errorf("start")
					}
				}
				fmt.Println("TUN_ACTIVE")
			case "DEACTIVATE":
				if tunScope != nil {
					if tunScope.Close() != nil {
						instance.Close()
						return fmt.Errorf("close")
					}
					tunScope = nil
				}
				fmt.Println("STANDBY_READY")
			default:
				if tunScope != nil {
					tunScope.Close()
				}
				instance.Close()
				return fmt.Errorf("frame")
			}
		}
		if tunScope != nil {
			tunScope.Close()
		}
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(input, 1))
	}
	if err = instance.Close(); err != nil {
		return fmt.Errorf("close")
	}
	fmt.Println("CLOSED")
	return nil
}
func main() {
	if err := run(); err != nil {
		stage := "CORE_UNKNOWN_FAILED"
		switch err.Error() {
		case "identity":
			stage = "CORE_IDENTITY_FAILED"
		case "arguments", "frame":
			stage = "CORE_INPUT_FAILED"
		case "configuration":
			stage = "CORE_CONFIGURATION_FAILED"
		case "create":
			stage = "CORE_CREATE_FAILED"
		case "start":
			stage = "CORE_START_FAILED"
		case "close":
			stage = "CORE_CLOSE_FAILED"
		}
		fmt.Fprintln(os.Stderr, stage)
		os.Exit(3)
	}
}
