//go:build windows && oracle_binding_lab

package tun

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
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

// Set by the lab-only build after compiling this commit's native executable.
var bindingLabNativeSHA256 string

type labSnapshot struct {
	PNP, Description, Hash string
	Count                  int
	Present, Matching      bool
}

// Independent CIM/PnP witness. Called before starting the helper, while already unbound,
// and after session timing is finished; the read-only script never mutates bindings.
func bindingSnapshot(ctx context.Context, luid winipcfg.LUID, stage string, original labSnapshot) (labSnapshot, error) {
	var result labSnapshot
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return result, err
	}
	utf := utf16.Encode([]rune(bindingLabScript))
	raw := make([]byte, len(utf)*2)
	for i, u := range utf {
		raw[2*i], raw[2*i+1] = byte(u), byte(u>>8)
	}
	audit := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	audit.Env = append(os.Environ(), "ORACLE_TEST_CREATED_LUID="+strconv.FormatUint(uint64(luid), 10), "ORACLE_TEST_AUDIT_STAGE="+stage, "ORACLE_TEST_BASELINE_PNP="+original.PNP, "ORACLE_TEST_BASELINE_DESC="+original.Description)
	output, err := audit.Output()
	if err != nil {
		return result, fmt.Errorf("CIM_QUERY_FAILED")
	}
	if err := json.Unmarshal(output, &result); err != nil || result.PNP == "" || result.Description == "" || result.Count <= 0 || len(result.Hash) != 64 {
		return result, fmt.Errorf("CIM_WITNESS_INVALID")
	}
	return result, nil
}

func logBindingPhase(t *testing.T, fields []string) bool {
	if len(fields) != 7 || fields[0] != "PHASE" || (fields[1] != "before" && fields[1] != "restore") {
		return false
	}
	var times [5]int64
	for i, v := range fields[2:] {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 || n > 90000 {
			return false
		}
		times[i] = n
	}
	t.Logf("NETCFG_%s LOCK_MS=%d IDENTIFY_MS=%d STAGE_MS=%d APPLY_MS=%d READBACK_MS=%d", fields[1], times[0], times[1], times[2], times[3], times[4])
	return true
}

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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := filepath.Join(os.Getenv("ProgramData"), "OracleProxyCandidateFixture")
	self, err := os.Executable()
	if err != nil || !strings.EqualFold(filepath.Clean(filepath.Dir(self)), filepath.Clean(fixture)) {
		t.Fatal("FIXTURE_EXECUTABLE_REQUIRED")
	}
	binary := filepath.Join(fixture, "binding-native.exe")
	content, err := os.ReadFile(binary)
	if err != nil || len(bindingLabNativeSHA256) != 64 || !strings.EqualFold(fmt.Sprintf("%x", sha256.Sum256(content)), bindingLabNativeSHA256) {
		t.Fatal("NATIVE_HELPER_DIGEST_MISMATCH")
	}
	original, err := bindingSnapshot(ctx, luid, "before", labSnapshot{})
	if err != nil || !original.Present || !original.Matching {
		t.Fatal("CIM_BASELINE_FAILED")
	}
	t.Logf("BIND_LAB_IDENTITY_before PNP_PRESENT=%t MATCHING_NIC=%t", original.Present, original.Matching)
	checkWitness := func(stage string) bool {
		auditCtx, stopAudit := context.WithTimeout(context.Background(), 15*time.Second)
		defer stopAudit()
		auditStarted := time.Now()
		observed, e := bindingSnapshot(auditCtx, luid, stage, original)
		t.Logf("CIM_%s_OTHER_BINDINGS_AUDIT_MS=%d", stage, time.Since(auditStarted).Milliseconds())
		if e != nil {
			t.Errorf("CIM_%s_QUERY_FAILED", stage)
			return false
		}
		t.Logf("BIND_LAB_IDENTITY_%s PNP_PRESENT=%t MATCHING_NIC=%t", stage, observed.Present, observed.Matching)
		if observed.PNP != original.PNP || !observed.Present || (stage == "restored" && !observed.Matching) {
			t.Errorf("CIM_%s_IDENTITY_FAILED", stage)
			return false
		}
		sameBindings := observed.Count == original.Count && observed.Hash == original.Hash
		t.Logf("CIM_%s_OTHER_BINDINGS_UNCHANGED=%t BINDING_ROWS=%d", stage, sameBindings, observed.Count)
		if !sameBindings {
			t.Errorf("CIM_%s_OTHER_BINDINGS_CHANGED", stage)
			return false
		}
		return true
	}
	shell := exec.CommandContext(ctx, binary)
	shell.Dir = fixture
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
	phaseReported := make(map[string]bool)
	logLine := func(line string) bool {
		if line == "READBACK 0" || line == "READBACK 1" {
			bindingReadback = line == "READBACK 1"
			t.Logf("BIND_LAB_BINDINGS_READBACK=%t", bindingReadback)
			return true
		}
		fields := strings.Fields(line)
		if logBindingPhase(t, fields) {
			if phaseReported[fields[1]] {
				t.Error("NETCFG_DUPLICATE_PHASE")
			}
			phaseReported[fields[1]] = true
			return true
		}
		switch line {
		case "FAILED_INPUT", "FAILED_SYSTEM", "FAILED_FIXTURE", "FAILED_COM", "FAILED_LOCK", "FAILED_INIT", "FAILED_IDENTITY", "FAILED_PNP", "FAILED_ENUM", "FAILED_PATH", "FAILED_BASELINE", "FAILED_DRIFT", "FAILED_STAGE", "FAILED_APPLY", "FAILED_REBOOT", "FAILED_READBACK", "FAILED_PARENT_ENDED", "FAILED_ROLLBACK", "ROLLBACK_FAILED":
			t.Log(line)
		}
		return false
	}
	expect := func(value string) bool {
		for n := 0; n < 16 && lines.Scan(); n++ {
			line := lines.Text()
			if line == value {
				return true
			}
			if !logLine(line) {
				return false
			}
		}
		return false
	}
	defer func() {
		_ = input.Close()
		complete := false
		for lines.Scan() {
			line := lines.Text()
			if line == "HELPER_COMPLETE" {
				complete = true
			} else {
				logLine(line)
			}
		}
		if restored && (!complete || !phaseReported["before"] || !phaseReported["restore"]) {
			t.Error("NATIVE_COMPLETION_WITNESS_MISSING")
		}
		if err := shell.Wait(); err != nil {
			t.Error("PROVIDER_OR_RESTORE_FAILED")
		}
		t.Logf("NATIVE_HELPER_EXIT=%d NATIVE_HELPER_ACK=%t", shell.ProcessState.ExitCode(), complete)
		checkWitness("restored")
	}()
	unbound := expect("UNBOUND")
	t.Logf("BIND_LAB_DISABLE_PROVIDER_ELAPSED_MS=%d", time.Since(started).Milliseconds())
	if !unbound {
		t.Fatal("BINDING_DISABLE_FAILED")
	}
	disableMs := time.Since(started).Milliseconds()
	checkWitness("unbound")
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
	providerReady := time.Since(click)
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
	adminReady := time.Since(click)
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
	dualIPReady := time.Since(click)
	if err = verifyOracleRecoveryIdentity(luid); err != nil {
		t.Fatal("CREATOR_CHANGED")
	}
	session, err := oraclePreparedAdapter.StartSession(0x400000)
	if err != nil {
		t.Fatal("SESSION_REOPEN_FAILED")
	}
	readyMs := time.Since(click).Milliseconds()
	defer session.End()
	t.Logf("BIND_LAB_RESTORE_CUMULATIVE_MS provider=%d admin=%d dual_ip=%d session=%d", providerReady.Milliseconds(), adminReady.Milliseconds(), dualIPReady.Milliseconds(), readyMs)
	empty = empty && bindingReadback
	t.Logf("DISABLE_INCLUDING_PROVIDER_START_MS=%d RESTORE_TO_EMPTY_SESSION_MS=%d STRICT_EMPTY=%t RESTORE_UNDER_1S=%t", disableMs, readyMs, empty, readyMs < 1000)
	if readyMs >= 1000 {
		t.Error("RESTORE_EXCEEDED_1S")
	}
	if !empty {
		t.Fatal("UNBIND_DID_NOT_PROVE_EMPTY")
	}
	labRoundTrip(t, luid, session, click)
}
