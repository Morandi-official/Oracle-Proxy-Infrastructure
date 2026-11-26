//go:build windows && oracle_binding_lab

package tun

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/sagernet/sing-tun/internal/winipcfg"
	"golang.org/x/sys/windows"
)

//go:embed bindinglab.ps1
var bindingLabScript string

// Read only this creator's complete GAA record. Never print an address, zone or suffix.
func labDefaultDNS(luid winipcfg.LUID) (int, bool) {
	rows, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)
	if err != nil {
		return -1, false
	}
	matches, count, mask := 0, 0, 0
	for _, row := range rows {
		if row == nil {
			return -1, false
		}
		if row.LUID != luid {
			continue
		}
		matches++
		for p := row.FirstDNSServerAddress; p != nil; p = p.Next {
			if count >= 256 || p.Address.Sockaddr == nil {
				return -1, false
			}
			count++
			if p.Address.Sockaddr.Addr.Family != windows.AF_INET6 {
				continue
			}
			ip, valid := netip.AddrFromSlice(p.Address.IP())
			if !valid {
				return -1, false
			}
			for i, s := range []string{"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"} {
				if ip == netip.MustParseAddr(s) {
					mask |= 1 << i
				}
			}
		}
	}
	if matches != 1 {
		return -1, false
	}
	return count, count == 3 && mask == 7
}

func TestDisposableOracleBindings(t *testing.T) {
	usr, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !usr.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Fatal("SYSTEM_REQUIRED")
	}
	marker, err := os.ReadFile(filepath.Join(os.Getenv("ProgramData"), "OracleProxyCandidateFixture", "authorized"))
	if err != nil || strings.TrimSpace(string(marker)) != "DISPOSABLE_GITHUB_ONLY" || os.Getenv("ORACLE_BINDING_LAB") != "DISPOSABLE_WINDOWS_RUNNER" {
		t.Fatal("FIXTURE_REQUIRED")
	}
	guid := generateGUIDByDeviceName("OracleProxy")
	absent := func() bool {
		rows, e := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
		if e != nil {
			return false
		}
		for _, row := range rows {
			if row.InterfaceGUID == *guid || row.Alias() == "OracleProxy" {
				return false
			}
		}
		return true
	}
	if !absent() {
		t.Fatal("PREEXISTING_DEVICE")
	}
	if err = PrepareOracleAdapter(); err != nil {
		t.Fatal("CREATE_FAILED")
	}
	luid := winipcfg.LUID(oraclePreparedAdapter.LUID())
	defer func() {
		ClosePreparedOracleAdapter()
		for n := 0; n < 40; n++ {
			if absent() {
				return
			}
			time.Sleep(75 * time.Millisecond)
		}
		t.Error("DEVICE_REMAINS")
	}()
	// The same creator and current source must independently reproduce the
	// persistent residual. This experiment never initiates a UDP peer.
	err = ParkOracleAdapter()
	time.Sleep(800 * time.Millisecond)
	if verifyOracleParkedEmpty(luid) == nil {
		t.Skip("ALREADY_STRICTLY_EMPTY")
	}
	if err == nil || (err.Error() != "PARK_IP_NOT_EMPTY" && err.Error() != "PARK_ROUTE_NOT_EMPTY") || !oracleParkedAdminDown {
		t.Fatal("WRONG_BASELINE")
	}
	if err = verifyOracleRecoveryIdentity(luid); err != nil {
		t.Fatal("RECEIPT_MISMATCH")
	}
	count, isDefault := labDefaultDNS(luid)
	t.Logf("BIND_LAB_DNS_COUNT=%d BIND_LAB_IPV6_DEFAULT_TRIPLET=%t", count, isDefault)
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal("SYSTEM_DIRECTORY")
	}
	utf := utf16.Encode([]rune(bindingLabScript))
	bytes := make([]byte, len(utf)*2)
	for i, u := range utf {
		bytes[2*i], bytes[2*i+1] = byte(u), byte(u>>8)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	shell := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes))
	shell.Env = append(os.Environ(), "ORACLE_TEST_CREATED_LUID="+strconv.FormatUint(uint64(luid), 10))
	input, err := shell.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := shell.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	shell.Stderr = io.Discard
	started := time.Now()
	if err = shell.Start(); err != nil {
		t.Fatal("PROVIDER_START")
	}
	lines := bufio.NewScanner(output)
	bindingReadback, restored := false, false
	expect := func(value string) bool {
		for n := 0; n < 6 && lines.Scan(); n++ {
			line := lines.Text()
			if line == "READBACK 0" || line == "READBACK 1" {
				bindingReadback = line == "READBACK 1"
				t.Logf("BIND_LAB_BINDINGS_READBACK=%t", bindingReadback)
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 4 && fields[0] == "IDENTITY" && (fields[1] == "before" || fields[1] == "unbound") {
				pv, pe := strconv.Atoi(fields[2])
				nv, ne := strconv.Atoi(fields[3])
				if pe == nil && ne == nil && pv >= -1 && pv <= 1 && nv >= -1 && nv <= 1 {
					t.Logf("BIND_LAB_IDENTITY_%s PNP_PRESENT=%d MATCHING_NIC=%d", fields[1], pv, nv)
				}
				continue
			}
			if strings.HasPrefix(line, "FAILED_") {
				switch line {
				case "FAILED_IDENTITY", "FAILED_REPLACED", "FAILED_BINDINGS", "FAILED_AMBIGUOUS", "FAILED_BINDING_CHANGE", "FAILED_BASELINE", "FAILED_STILL_BOUND", "FAILED_PARENT_ENDED", "FAILED_ROLLBACK", "FAILED_OTHER_BINDINGS_CHANGED", "FAILED_PROVIDER":
					t.Log(line)
				}
			}
			return line == value
		}
		return false
	}
	defer func() {
		_ = input.Close()
		if restored && !expect("OTHERS_UNCHANGED") {
			t.Error("OTHER_BINDINGS_READBACK_FAILED")
		}
		if shell.Wait() != nil {
			t.Error("PROVIDER_OR_RESTORE_FAILED")
		}
	}()
	unbound := expect("UNBOUND")
	t.Logf("BIND_LAB_DISABLE_PROVIDER_ELAPSED_MS=%d", time.Since(started).Milliseconds())
	if !unbound {
		t.Fatal("BINDING_DISABLE_FAILED")
	}
	disableMs := time.Since(started).Milliseconds()
	var empty bool
	for n := 0; n < 25; n++ {
		empty = verifyOracleParkedEmpty(luid) == nil
		if empty {
			break
		}
		time.Sleep(80 * time.Millisecond)
	}
	time.Sleep(800 * time.Millisecond)
	empty = verifyOracleParkedEmpty(luid) == nil && empty
	var gaaMatches = -1
	if rows, e := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces); e == nil {
		gaaMatches = 0
		for _, row := range rows {
			if row == nil {
				gaaMatches = -1
				break
			}
			if row.LUID == luid {
				gaaMatches++
			}
		}
	}
	round, roundErr := winipcfg.LUIDFromGUID(guid)
	t.Logf("UNBOUND_CREATOR_HANDLE_SAME=%t UNBOUND_GUID_LUID_SAME=%t UNBOUND_GAA_MATCHES=%d", uint64(luid) == oraclePreparedAdapter.LUID(), roundErr == nil && round == luid, gaaMatches)
	oracleLogParkedCounts(luid, "unbound")
	count, isDefault = labDefaultDNS(luid)
	t.Logf("UNBOUND_DNS_COUNT=%d UNBOUND_IPV6_DEFAULT_TRIPLET=%t", count, isDefault)
	click := time.Now()
	_, err = fmt.Fprintln(input, "RESTORE")
	if err != nil || !expect("RESTORED") {
		t.Fatal("BINDINGS_NOT_RESTORED")
	}
	restored = true
	row, err := luid.Interface()
	if err != nil || row.InterfaceGUID != *guid || row.InterfaceLUID != luid {
		t.Fatal("RESTORE_IDENTITY_FAILED")
	}
	if row.AdminStatus == winipcfg.NetIfAdminStatusDown {
		if err = setOracleParkedAdmin(luid, winipcfg.NetIfAdminStatusDown, winipcfg.NetIfAdminStatusUp); err != nil {
			t.Fatal("ADMIN_RESTORE_FAILED")
		}
	} else if row.AdminStatus != winipcfg.NetIfAdminStatusUp {
		t.Fatal("UNEXPECTED_ADMIN_STATE")
	}
	for n := 0; n < 100; n++ {
		_, v4 := luid.IPInterface(windows.AF_INET)
		_, v6 := luid.IPInterface(windows.AF_INET6)
		if v4 == nil && v6 == nil {
			break
		}
		if n == 99 {
			t.Fatal("IP_STACK_NOT_READY")
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err = verifyOracleRecoveryIdentity(luid); err != nil {
		t.Fatal("CREATOR_CHANGED")
	}
	session, err := oraclePreparedAdapter.StartSession(0x400000)
	if err != nil {
		t.Fatal("SESSION_REOPEN_FAILED")
	}
	readyMs := time.Since(click).Milliseconds()
	session.End()
	empty = empty && bindingReadback
	t.Logf("DISABLE_INCLUDING_PROVIDER_START_MS=%d RESTORE_TO_EMPTY_SESSION_MS=%d STRICT_EMPTY=%t RESTORE_UNDER_1S=%t", disableMs, readyMs, empty, readyMs < 1000)
	if readyMs >= 1000 {
		t.Error("RESTORE_EXCEEDED_1S")
	}
	if !empty {
		t.Fatal("UNBIND_DID_NOT_PROVE_EMPTY")
	}
}
