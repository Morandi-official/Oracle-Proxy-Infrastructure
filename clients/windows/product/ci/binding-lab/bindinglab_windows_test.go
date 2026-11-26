//go:build windows && oracle_binding_lab

package tun

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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
	TargetUnique              bool
	AllowedUnbound            []string
	PNP, Description, Hash    string
	TargetHash, TargetOffHash string
	TargetCount, IP4, IP6     int
	Count                     int
	Present, Matching         bool
	TargetRows                []labTargetRow
}

type labTargetRow struct {
	Kind, Raw, Instance, Descriptor string
	Enabled                         bool
}

// Compare identities within this disposable job, without publishing a stable
// cross-host fingerprint. Tokens are HMAC-SHA256(key, field || NUL || UTF8(value))[:12].
var labReportKey = func() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}()

func knownComponentTokens() map[string]string {
	result := make(map[string]string)
	for _, id := range strings.Fields("ms_tcpip ms_tcpip6 ms_msclient ms_server ms_pacer ms_lldp ms_lltdio ms_rspndr ms_ndiscap ms_wfplwf_lower ms_wfplwf_upper ms_l1vhlwf ms_implat ms_ndisuio ms_netbios ms_netbt ms_wanarp ms_wanarpv6 ms_bridge ms_pppoe ms_netbios_smb vms_pp") {
		h := hmac.New(sha256.New, labReportKey)
		h.Write([]byte("kind\x00" + id))
		result[hex.EncodeToString(h.Sum(nil)[:12])] = id
	}
	return result
}

func bindingRowCounts(rows []labTargetRow, labels map[string]string, ipOff bool) (map[string][2]int, bool) {
	counts := make(map[string][2]int)
	for _, row := range rows {
		for _, token := range []string{row.Kind, row.Raw, row.Instance, row.Descriptor} {
			if len(token) != 24 || strings.Trim(token, "0123456789abcdef") != "" {
				return nil, false
			}
		}
		label := labels[row.Kind]
		if label == "" {
			label = "anon-" + row.Kind
		}
		key := fmt.Sprintf("component=%s instance=%s component_token=%s description_token=%s", label, row.Instance, row.Raw, row.Descriptor)
		state := 0
		if row.Enabled && !(ipOff && (label == "ms_tcpip" || label == "ms_tcpip6")) {
			state = 1
		}
		count := counts[key]
		count[state]++
		counts[key] = count
	}
	return counts, true
}

// Each tuple reports the number of disabled/enabled copies of the exact row.
// A replaced CIM instance emits a removed row and an added row, even if the
// enabled value and normalized component ID were the same before and after.
func logTargetRows(t *testing.T, stage string, original, observed labSnapshot) {
	if len(original.TargetRows) != original.TargetCount || len(observed.TargetRows) != observed.TargetCount ||
		original.TargetCount < 1 || observed.TargetCount < 1 || original.TargetCount > 128 || observed.TargetCount > 128 {
		t.Logf("CIM_%s_TARGET_ROW_DETAIL_UNAVAILABLE", stage)
		return
	}
	labels := knownComponentTokens()
	before, ok1 := bindingRowCounts(original.TargetRows, labels, false)
	expected, ok2 := bindingRowCounts(original.TargetRows, labels, stage == "unbound")
	now, ok3 := bindingRowCounts(observed.TargetRows, labels, false)
	if !ok1 || !ok2 || !ok3 {
		t.Logf("CIM_%s_TARGET_ROW_DETAIL_INVALID", stage)
		return
	}
	keys := make([]string, 0, len(before)+len(now))
	for key := range before {
		keys = append(keys, key)
	}
	for key := range now {
		if _, found := before[key]; !found {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	mismatches := 0
	for _, key := range keys {
		b, w, a := before[key], expected[key], now[key]
		if w != a {
			mismatches++
		}
		if stage == "before" || w != a || b != a {
			t.Logf("CIM_%s_TARGET_ROW %s BEFORE_OFF_ON=%d/%d EXPECTED_OFF_ON=%d/%d OBSERVED_OFF_ON=%d/%d", stage, key, b[0], b[1], w[0], w[1], a[0], a[1])
		}
	}
	t.Logf("CIM_%s_TARGET_MISMATCHED_ROW_KEYS=%d", stage, mismatches)
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
	audit.Env = append(os.Environ(), "ORACLE_TEST_CREATED_LUID="+strconv.FormatUint(uint64(luid), 10), "ORACLE_TEST_BINDING_REPORT_KEY="+base64.StdEncoding.EncodeToString(labReportKey), "ORACLE_TEST_AUDIT_STAGE="+stage, "ORACLE_TEST_BASELINE_PNP="+original.PNP, "ORACLE_TEST_BASELINE_DESC="+original.Description)
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
	if len(fields) < 2 || (fields[1] != "before" && fields[1] != "restore" && fields[1] != "rollback") {
		return false
	}
	switch fields[0] {
	case "PHASE":
		if len(fields) != 7 {
			return false
		}
	case "SETTLE":
		if len(fields) != 6 {
			return false
		}
	default:
		return false
	}
	var values [5]int64
	for i, v := range fields[2:] {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n > 90000 {
			return false
		}
		values[i] = int64(n)
	}
	if fields[0] == "SETTLE" {
		t.Logf("NETCFG_SETTLE_%s ATTEMPTS=%d PNP_MS=%d GRAPH_MS=%d FINISH_MS=%d", fields[1], values[0], values[1], values[2], values[3])
	} else {
		t.Logf("NETCFG_%s LOCK_MS=%d IDENTIFY_MS=%d STAGE_MS=%d APPLY_MS=%d READBACK_MS=%d", fields[1], values[0], values[1], values[2], values[3], values[4])
	}
	return true
}

// Snapshot the IP Helper tables independently of NetCfg or CIM, including after
// abnormal helper exit. A missing IP interface does not prove a binding state.
func logLabIPInterfaces(t *testing.T, luid winipcfg.LUID, stage string) {
	v4, e4 := luid.IPInterface(windows.AF_INET)
	v6, e6 := luid.IPInterface(windows.AF_INET6)
	t.Logf("BIND_LAB_%s_IP_INTERFACE V4=%t V6=%t", stage, e4 == nil && v4 != nil && v4.InterfaceLUID == luid, e6 == nil && v6 != nil && v6.InterfaceLUID == luid)
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
	logLabIPInterfaces(t, luid, "before")
	original, err := bindingSnapshot(ctx, luid, "before", labSnapshot{})
	if err != nil || !original.Present || !original.Matching {
		t.Fatal("CIM_BASELINE_FAILED")
	}
	logTargetRows(t, "before", original, original)
	t.Logf("CIM_before_TARGET_BINDINGS ROWS=%d IPV4_ENABLED=%d IPV6_ENABLED=%d", original.TargetCount, original.IP4, original.IP6)
	if original.TargetCount < 2 || original.IP4 != 1 || original.IP6 != 1 || len(original.TargetHash) != 64 || len(original.TargetOffHash) != 64 || original.TargetHash == original.TargetOffHash {
		t.Fatal("CIM_TARGET_BASELINE_UNVERIFIED")
	}
	if !original.TargetUnique || len(original.AllowedUnbound) == 0 || len(original.AllowedUnbound) > 16 || !slices.Contains(original.AllowedUnbound, original.TargetOffHash) {
		t.Fatal("CIM_TARGET_IDENTITIES_OR_DEPENDENCY_BASELINE_UNVERIFIED")
	}
	t.Logf("BIND_LAB_IDENTITY_before PNP_PRESENT=%t MATCHING_NIC=%t", original.Present, original.Matching)
	checkWitness := func(stage string) bool {
		logLabIPInterfaces(t, luid, stage)
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
		logTargetRows(t, stage, original, observed)
		sameBindings := observed.Count == original.Count && observed.Hash == original.Hash
		t.Logf("CIM_%s_OTHER_BINDINGS_UNCHANGED=%t BINDING_ROWS=%d", stage, sameBindings, observed.Count)
		if !sameBindings {
			t.Errorf("CIM_%s_OTHER_BINDINGS_CHANGED", stage)
		}
		wantEnabled := 1
		inventoryMatches := observed.TargetHash == original.TargetHash
		if stage == "unbound" {
			wantEnabled = 0
			inventoryMatches = slices.Contains(original.AllowedUnbound, observed.TargetHash)
			t.Logf("CIM_unbound_IP_ONLY_HASH_MATCH=%t TARGET_DEPENDENCY_CANDIDATE_MATCH=%t", observed.TargetHash == original.TargetOffHash, inventoryMatches)
		}
		targetMatches := observed.TargetUnique && observed.TargetCount == original.TargetCount && inventoryMatches && observed.IP4 == wantEnabled && observed.IP6 == wantEnabled
		t.Logf("CIM_%s_TARGET_BINDINGS ROWS=%d IPV4_ENABLED=%d IPV6_ENABLED=%d EXPECTED_CHOICES=%t", stage, observed.TargetCount, observed.IP4, observed.IP6, targetMatches)
		if !targetMatches {
			t.Errorf("CIM_%s_TARGET_BINDINGS_UNVERIFIED", stage)
		}
		return sameBindings && targetMatches
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
			key := fields[0] + "_" + fields[1]
			if phaseReported[key] {
				t.Error("NETCFG_DUPLICATE_PHASE")
			}
			phaseReported[key] = true
			return true
		}
		switch line {
		case "FAILED_INPUT", "FAILED_SYSTEM", "FAILED_FIXTURE", "FAILED_COM", "FAILED_LOCK", "FAILED_INIT", "FAILED_IDENTITY", "FAILED_PNP", "FAILED_ENUM", "FAILED_PATH", "FAILED_BASELINE", "FAILED_DRIFT", "FAILED_STAGE", "FAILED_APPLY", "FAILED_REBOOT", "FAILED_READBACK", "FAILED_PARENT_ENDED", "FAILED_ROLLBACK", "ROLLBACK_FAILED":
			t.Log(line)
		}
		if len(fields) > 0 && (fields[0] == "SETTLE" || fields[0] == "PHASE") {
			t.Error("NETCFG_INVALID_PHASE_REPORT")
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
		if restored && (!complete || !phaseReported["PHASE_before"] || !phaseReported["PHASE_restore"] || !phaseReported["SETTLE_before"] || !phaseReported["SETTLE_restore"]) {
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
