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
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	oracleTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"golang.org/x/sys/windows"
)

func run() error {
	check := len(os.Args) == 2 && os.Args[1] == "--check"
	eagerProbe := len(os.Args) == 2 && os.Args[1] == "--standby-probe"
	holderOnly := len(os.Args) == 2 && os.Args[1] == "--adapter-holder"
	standby := len(os.Args) == 2 && os.Args[1] == "--standby" || eagerProbe || holderOnly
	recoveryMode := parseAdapterRecoveryMode(os.Args[1:])
	recoverAdapter := recoveryMode != recoveryNone
	if !check && !standby && !recoverAdapter && len(os.Args) != 1 {
		return fmt.Errorf("arguments")
	}
	if !check {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil || user.User.Sid.String() != "S-1-5-18" {
			return fmt.Errorf("identity")
		}
	}
	if recoverAdapter || holderOnly {
		var session uint32
		if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session != 0 {
			return fmt.Errorf("identity")
		}
	}
	if recoverAdapter {
		request, err := readAdapterRecoveryRequest(os.Stdin)
		if err != nil {
			return fmt.Errorf("frame")
		}
		if recoveryMode == recoveryDormant {
			err = oracleTun.RecoverDormantOracleAdapter(request.LUID, restoreAdapterBindings)
		} else {
			err = oracleTun.RecoverOracleAdapter(request.LUID, restoreAdapterBindings)
		}
		if err != nil {
			switch err.Error() {
			case "PARK_BINDINGS_LOAD_FAILED", "PARK_BINDINGS_RESTORE_FAILED", "ORPHAN_IDENTITY_FAILED", "ORPHAN_IP_CLEANUP_FAILED", "ORPHAN_ROUTE_CLEANUP_FAILED", "ORPHAN_DNS_CLEANUP_FAILED", "ORPHAN_RECREATE_FAILED", "ORPHAN_VERIFY_FAILED":
				fmt.Fprintln(os.Stderr, err.Error())
			case "DORMANT_IP_QUERY_FAILED", "DORMANT_IP_NOT_EMPTY", "DORMANT_ROUTE_QUERY_FAILED", "DORMANT_ROUTE_NOT_EMPTY", "DORMANT_DNS_QUERY_FAILED", "DORMANT_DNS_NOT_EMPTY", "DORMANT_RECREATE_FAILED", "DORMANT_VERIFY_FAILED":
				fmt.Fprintln(os.Stderr, err.Error())
			case "DORMANT_ROUTE_PROTOCOL_NOT_LOCAL", "DORMANT_ROUTE_NEXT_HOP_UNSAFE", "DORMANT_ROUTE_DESTINATION_UNSAFE":
				fmt.Fprintln(os.Stderr, err.Error())
			}
			return fmt.Errorf("adapter-recovery")
		}
		fmt.Println("ADAPTER_RECOVERED")
		return nil
	}
	defer oracleTun.ClosePreparedOracleAdapter()
	input := bufio.NewReaderSize(os.Stdin, 65536)
	// An explicitly attached UI may prepare only the process-owned Wintun handle.
	if holderOnly {
		// The SYSTEM service sends HOLD only after assigning this process to
		// its kill-on-close job. EOF during launch cannot create an adapter.
		if err := authorizeHolderStart(input); err != nil {
			return err
		}
		if err := oracleTun.PrepareOracleAdapter(); err != nil {
			return fmt.Errorf("create")
		}
	}
	serve := func(resumed bool) (bool, error) {
		return runPeerGeneration(input, check, standby, eagerProbe || resumed, resumed)
	}
	park := func() error { return oracleTun.ParkOracleAdapter(parkAdapterBindings, restoreAdapterBindings) }
	err := serveAdapterLifetimes(input, holderOnly, serve, checkedAdapterAudit(park), checkedAdapterAudit(oracleTun.VerifyParkedOracleAdapter), func() {
		// Both pipes are ordered separately. The parent consumes this stderr
		// fence and stdout receipt before it arms a new proof in the same PID.
		fmt.Fprintln(os.Stderr, "PARK_FENCE")
		fmt.Println("PARKED")
	})
	if err == nil && !check {
		fmt.Println("CLOSED")
	}
	return err
}

// Preserve one fixed native reason when the host cannot retain an empty device.
func checkedAdapterAudit(audit func() error) func() error {
	return func() error {
		err := audit()
		if err != nil {
			reason := "PARK_QUERY_FAILED"
			switch code := err.Error(); code {
			case "PARK_CREATOR_MISSING", "PARK_IP_QUERY_FAILED", "PARK_IP_NOT_EMPTY",
				"PARK_ROUTE_QUERY_FAILED", "PARK_ROUTE_NOT_EMPTY", "PARK_DNS_NOT_EMPTY",
				"PARK_DNS_SERVER_PRESENT", "PARK_DNS_SUFFIX_PRESENT", "PARK_DNS4_CLEAR_FAILED", "PARK_DNS6_CLEAR_FAILED", "PARK_DNS_LIST_INVALID",
				"PARK_INTERFACE_QUERY_FAILED", "PARK_BINDINGS_LOAD_FAILED", "PARK_BINDINGS_DISABLE_FAILED", "PARK_BINDINGS_RESTORE_FAILED",
				"ORPHAN_IDENTITY_FAILED", "DORMANT_IP_QUERY_FAILED", "DORMANT_IP_NOT_EMPTY",
				"DORMANT_ROUTE_QUERY_FAILED", "DORMANT_ROUTE_NOT_EMPTY", "DORMANT_DNS_QUERY_FAILED", "DORMANT_DNS_NOT_EMPTY",
				"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL", "DORMANT_ROUTE_NEXT_HOP_UNSAFE", "DORMANT_ROUTE_DESTINATION_UNSAFE":
				reason = code
			}
			fmt.Fprintln(os.Stderr, "PARK_AUDIT_FAILED", reason)
		}
		return err
	}
}

// Each invocation owns one complete transport lifetime. No Box, key, SOCKS
// credential, probe or peer is reachable from the sessionless command loop.
func runPeerGeneration(input *bufio.Reader, check, standby, eagerProbe, resumed bool) (park bool, result error) {
	line, err := input.ReadSlice('\n')
	if err != nil || len(line) > 65536 {
		clear(line)
		return false, fmt.Errorf("frame")
	}
	ctx := productContext()
	ctx = pause.WithDefaultManager(service.ContextWithDefaultRegistry(ctx))
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, line)
	clear(line)
	if err != nil {
		return false, fmt.Errorf("configuration")
	}
	var tun option.Inbound
	if standby {
		inbounds := options.Inbounds[:0]
		for _, inbound := range options.Inbounds {
			if inbound.Type == "tun" {
				if tun.Type != "" || inbound.Tag != "device" {
					return false, fmt.Errorf("configuration")
				}
				tun = inbound
			} else {
				inbounds = append(inbounds, inbound)
			}
		}
		if tun.Type == "" {
			return false, fmt.Errorf("configuration")
		}
		options.Inbounds = inbounds
	}
	// A freshly owned, sessionless adapter and private endpoint startup are
	// independent. Join creation before READY and before any deferred close.
	// No route, address, packet session or user traffic is activated here.
	var adapterReady func() error
	if standby && !check {
		prepare := oracleTun.PrepareOracleAdapter
		if resumed {
			// The authenticated fresh config is already parsed. Restore the
			// exact protocol paths while the new private peer/probe starts.
			// User routes/TUN can be enabled only after both paths are ready.
			prepare = checkedAdapterAudit(oracleTun.ResumeOracleAdapterBindings)
		}
		adapterReady = beginAdapterPreparation(prepare)
		defer func() { _ = adapterReady() }()
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return false, fmt.Errorf("create")
	}
	if check {
		fmt.Println("CONFIG_VALID")
		return false, nil
	}
	defer func() {
		if closeErr := instance.Close(); closeErr != nil && result == nil {
			result = fmt.Errorf("close")
		}
	}()
	if err = instance.Start(); err != nil {
		return false, fmt.Errorf("start")
	}
	// Only the attested parent uses this private startup mode. SOCKS is
	// credential protected; ordinary TUN routing remains inactive.
	if eagerProbe {
		if endpoint, ok := instance.Endpoint().Get("oracle-wireguard"); ok {
			stopProof := startInitialHTTP3(ctx, endpoint)
			defer stopProof()
		}
		fmt.Println("PROBE_READY")
	}
	if adapterReady != nil {
		err = adapterReady()
		if err != nil {
			return false, fmt.Errorf("create")
		}
	}
	fmt.Println("READY")
	if !standby {
		_, _ = io.Copy(io.Discard, io.LimitReader(input, 1))
		return false, nil
	}
	return serveStandbyTun(input, ctx, instance, tun)
}

func serveStandbyTun(input *bufio.Reader, ctx context.Context, instance *box.Box, tun option.Inbound) (park bool, result error) {
	var tunScope *adapter.Scope
	defer func() {
		if tunScope != nil {
			if err := tunScope.Close(); err != nil && result == nil {
				result = fmt.Errorf("close")
			}
		}
	}()
	for {
		command, err := readCoreCommand(input)
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		switch command {
		case "ACTIVATE":
			if tunScope == nil {
				logger := instance.LogFactory().NewLogger("standby-tun")
				entry, err := productInbounds().Create(ctx, instance.Router(), logger, tun.Tag, tun.Type, tun.Options)
				if err != nil {
					return false, fmt.Errorf("start")
				}
				lifecycle, ok := entry.(adapter.Lifecycle)
				if !ok {
					return false, fmt.Errorf("start")
				}
				tunScope = adapter.NewScope(ctx, logger)
				for _, stage := range adapter.ListStartStages {
					if err := tunScope.Start("device", lifecycle, stage); err != nil {
						return false, fmt.Errorf("start")
					}
				}
			}
			fmt.Println("TUN_ACTIVE")
		case "DEACTIVATE":
			if tunScope != nil {
				if err := tunScope.Close(); err != nil {
					return false, fmt.Errorf("close")
				}
				tunScope = nil
			}
			fmt.Println("STANDBY_READY")
		case "PARK":
			return true, nil
		default:
			return false, fmt.Errorf("frame")
		}
	}
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
		case "adapter-recovery":
			stage = "CORE_ADAPTER_RECOVERY_FAILED"
		}
		fmt.Fprintln(os.Stderr, stage)
		os.Exit(3)
	}
}
