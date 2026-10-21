//go:build windows

// SPDX-License-Identifier: GPL-3.0-or-later
// Private child of OracleProxyService. Configuration stays in a pipe, never a
// plaintext file or command line. EOF requests graceful route/DNS cleanup.
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"golang.org/x/sys/windows"
)

func run() error {
	check := len(os.Args) == 2 && os.Args[1] == "--check"
	if !check && len(os.Args) != 1 {
		return fmt.Errorf("arguments")
	}
	if !check {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user.User.Sid.String() != "S-1-5-18" {
			return fmt.Errorf("identity")
		}
	}
	input := bufio.NewReaderSize(os.Stdin, 65536)
	line, err := input.ReadSlice('\n')
	if err != nil || len(line) > 65536 {
		return fmt.Errorf("frame")
	}
	registry := include.OutboundRegistry()
	outbound.Register[relayOptions](registry, relayType, newRelayOutbound)
	ctx := box.Context(context.Background(), include.InboundRegistry(), registry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry(), include.CertificateProviderRegistry())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, line)
	for i := range line {
		line[i] = 0
	}
	if err != nil {
		return fmt.Errorf("configuration")
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
	// No arbitrary command interface. The owning SYSTEM process closes this
	// anonymous pipe to stop gracefully; unexpected input also shuts down.
	_, _ = io.Copy(io.Discard, io.LimitReader(input, 1))
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
