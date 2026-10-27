"""Apply pinned Windows route/lifecycle and receipt-bound recovery changes.

Normal routing prefixes, gateways, metrics and policy are unchanged. Recovery
can only clear the exact fixed-GUID/LUID orphan validated by the SYSTEM parent;
it never adopts an existing adapter by name or uninstalls a driver. The modified
dependency source is included in corresponding-source.zip.
"""
import hashlib
from pathlib import Path
import sys

TARGET = Path(__file__).resolve().parents[1] / 'core/vendor/github.com/sagernet/sing-tun/tun_windows.go'
PREIMAGE = 'b0e7348b6fee66dbef5fe0851585d10ce2c07691c353cd14b3af4383ab09bb5c'
CACHE = '''// Oracle Proxy keeps only its own unconfigured, sessionless adapter between
// explicit Off and On. This avoids repeated Windows PnP removal/creation.
var oracleAdapterMutex sync.Mutex
var oraclePreparedAdapter *wintun.Adapter

func openOracleAdapter(name string) (*wintun.Adapter, error) {
	if name == "OracleProxy" {
		oracleAdapterMutex.Lock()
		prepared := oraclePreparedAdapter
		oraclePreparedAdapter = nil
		oracleAdapterMutex.Unlock()
		if prepared != nil {
			return prepared, nil
		}
	}
	adapter, err := wintun.CreateAdapter(name, TunnelType, generateGUIDByDeviceName(name))
	// A cold caller must never adopt an unrelated same-name adapter.
	return adapter, err
}

func ClosePreparedOracleAdapter() {
	oracleAdapterMutex.Lock()
	defer oracleAdapterMutex.Unlock()
	if oraclePreparedAdapter != nil {
		oraclePreparedAdapter.Close()
		oraclePreparedAdapter = nil
	}
}

// Create only this process's private, sessionless adapter before READY. No
// addresses, routes, DNS or packet session may be retained in standby. Do not
// adopt a preexisting adapter: the authenticated parent verifies removal first.
func PrepareOracleAdapter() error {
	oracleAdapterMutex.Lock()
	prepared := oraclePreparedAdapter != nil
	oracleAdapterMutex.Unlock()
	if prepared { return nil }
	adapter, err := wintun.CreateAdapter("OracleProxy", TunnelType, generateGUIDByDeviceName("OracleProxy"))
	if err != nil { return err }
	owned := &NativeTun{adapter: adapter, options: Options{Name: "OracleProxy"}}
	if err = owned.prepareOracleAdapter(); err != nil {
		adapter.Close()
		return err
	}
	return nil
}

func (t *NativeTun) prepareOracleAdapter() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	// Scope is closed while the parent's persistent fail-close guard is still
	// active. Remove addresses, routes and DNS before acknowledging standby.
	if err := luid.FlushIPAddresses(windows.AF_UNSPEC); err != nil {
		fmt.Fprintln(os.Stderr, "TUN_CLEANUP_IP_FAILED")
		return err
	}
	if err := luid.FlushRoutes(windows.AF_UNSPEC); err != nil {
		fmt.Fprintln(os.Stderr, "TUN_CLEANUP_ROUTE_FAILED")
		return err
	}
	if err := luid.FlushDNS(windows.AF_INET); err != nil {
		fmt.Fprintln(os.Stderr, "TUN_CLEANUP_DNS4_FAILED")
		return err
	}
	if err := luid.FlushDNS(windows.AF_INET6); err != nil {
		fmt.Fprintln(os.Stderr, "TUN_CLEANUP_DNS6_FAILED")
		return err
	}
	oracleAdapterMutex.Lock()
	defer oracleAdapterMutex.Unlock()
	if oraclePreparedAdapter != nil {
		return os.ErrExist
	}
	oraclePreparedAdapter = t.adapter
	return nil
}

'''
RECOVERY = '''// RecoverOracleAdapter is reachable only through the pinned SYSTEM recovery
// child. Its parent supplies a protected fresh-creation receipt after proving
// the creator exited. This function independently fences every mutation to the
// fixed GUID, exact LUID, alias, type and down state. It never opens an adapter
// by name, deletes a driver, or accepts a general interface target.
func RecoverOracleAdapter(value uint64) error {
	oracleAdapterMutex.Lock()
	defer oracleAdapterMutex.Unlock()
	if value == 0 || oraclePreparedAdapter != nil { return fmt.Errorf("ORPHAN_IDENTITY_FAILED") }
	luid := winipcfg.LUID(value)
	if err := verifyOracleRecoveryIdentity(luid); err != nil { return err }
	flushErr := flushOracleRecoveryInterface(luid)
	if flushErr != nil && flushErr.Error() == "ORPHAN_IDENTITY_FAILED" { return flushErr }
	absent, err := oracleRecoveryAbsent()
	if err != nil { return fmt.Errorf("ORPHAN_VERIFY_FAILED") }
	if absent { return nil }
	// A crashed creator may leave IP-stack references after its device is gone.
	// Only a successful fresh Create gives this process deletion ownership. A
	// Create collision is refused; OpenAdapter is deliberately never a fallback.
	if err = verifyOracleRecoveryIdentity(luid); err != nil { return err }
	created, err := wintun.CreateAdapter("OracleProxy", TunnelType, generateGUIDByDeviceName("OracleProxy"))
	if err != nil { return fmt.Errorf("ORPHAN_RECREATE_FAILED") }
	fresh := winipcfg.LUID(created.LUID())
	err = verifyOracleRecoveryIdentity(fresh)
	if err == nil { err = flushOracleRecoveryInterface(fresh) }
	// WintunCloseAdapter has void ABI. The wrapper's nominal error is not an
	// absence proof. Close only this successful Create's own creator handle.
	created.Close()
	if err != nil && err.Error() == "ORPHAN_IDENTITY_FAILED" { return err }
	// Auto-generated routes or a detached device's DNS API may reject a flush.
	// That never grants success while a row remains. A successful independent
	// table query after closing our creator is the sole completion proof.
	for attempt := 0; attempt < 30; attempt++ {
		absent, queryErr := oracleRecoveryAbsent()
		if queryErr != nil { return fmt.Errorf("ORPHAN_VERIFY_FAILED") }
		if absent { return nil }
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil { return err }
	if flushErr != nil { return flushErr }
	return fmt.Errorf("ORPHAN_VERIFY_FAILED")
}

func verifyOracleRecoveryIdentity(luid winipcfg.LUID) error {
	fail := fmt.Errorf("ORPHAN_IDENTITY_FAILED")
	expected := generateGUIDByDeviceName("OracleProxy")
	guid, err := luid.GUID()
	if err != nil || *guid != *expected { return fail }
	roundTrip, err := winipcfg.LUIDFromGUID(expected)
	if err != nil || roundTrip != luid { return fail }
	row, err := luid.Interface()
	if err != nil || row.InterfaceLUID != luid || row.InterfaceGUID != *expected ||
		row.Alias() != "OracleProxy" || row.Description() != "sing-tun Tunnel" ||
		row.Type != winipcfg.IfTypePropVirtual || row.OperStatus != winipcfg.IfOperStatusDown { return fail }
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil { return fail }
	matches := 0
	for _, entry := range rows {
		if entry.Alias() == "OracleProxy" || entry.InterfaceGUID == *expected {
			if entry.InterfaceLUID != luid || entry.InterfaceGUID != *expected || entry.Alias() != "OracleProxy" { return fail }
			matches++
		}
	}
	if matches != 1 { return fail }
	return nil
}

func flushOracleRecoveryInterface(luid winipcfg.LUID) error {
	// Revalidate the same immutable interface identity before each phase.
	if err := verifyOracleRecoveryIdentity(luid); err != nil { return err }
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("ORPHAN_IP_CLEANUP_FAILED") }
	for i := range addresses {
		if addresses[i].InterfaceLUID == luid {
			if err = addresses[i].Delete(); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) { return fmt.Errorf("ORPHAN_IP_CLEANUP_FAILED") }
		}
	}
	if absent, queryErr := oracleRecoveryAbsent(); queryErr == nil && absent { return nil }
	if err = verifyOracleRecoveryIdentity(luid); err != nil { return err }
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("ORPHAN_ROUTE_CLEANUP_FAILED") }
	for i := range routes {
		if routes[i].InterfaceLUID == luid {
			if err = routes[i].Delete(); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) { return fmt.Errorf("ORPHAN_ROUTE_CLEANUP_FAILED") }
		}
	}
	if absent, queryErr := oracleRecoveryAbsent(); queryErr == nil && absent { return nil }
	if err = verifyOracleRecoveryIdentity(luid); err != nil { return err }
	// Recovery requires the Windows 10 1809+ DNS API directly. Do not fall back
	// to netsh/PowerShell or execute any command based on interface metadata.
	empty, err := windows.UTF16PtrFromString("")
	if err != nil { return fmt.Errorf("ORPHAN_DNS_CLEANUP_FAILED") }
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		settings := &winipcfg.DnsInterfaceSettings{Version: winipcfg.DnsInterfaceSettingsVersion1,
			Flags: winipcfg.DnsInterfaceSettingsFlagNameserver | winipcfg.DnsInterfaceSettingsFlagSearchList,
			NameServer: empty, SearchList: empty}
		if family == windows.AF_INET6 { settings.Flags |= winipcfg.DnsInterfaceSettingsFlagIPv6 }
		if err = winipcfg.SetInterfaceDnsSettings(*generateGUIDByDeviceName("OracleProxy"), settings); err != nil {
			if absent, queryErr := oracleRecoveryAbsent(); queryErr == nil && absent { return nil }
			return fmt.Errorf("ORPHAN_DNS_CLEANUP_FAILED")
		}
	}
	addresses, err = winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("ORPHAN_IP_CLEANUP_FAILED") }
	for _, entry := range addresses { if entry.InterfaceLUID == luid { return fmt.Errorf("ORPHAN_IP_CLEANUP_FAILED") } }
	routes, err = winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("ORPHAN_ROUTE_CLEANUP_FAILED") }
	for _, entry := range routes { if entry.InterfaceLUID == luid { return fmt.Errorf("ORPHAN_ROUTE_CLEANUP_FAILED") } }
	servers, err := luid.DNS()
	if err != nil || len(servers) != 0 { return fmt.Errorf("ORPHAN_DNS_CLEANUP_FAILED") }
	return nil
}

func oracleRecoveryAbsent() (bool, error) {
	rows, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormal)
	if err != nil { return false, err }
	expected := generateGUIDByDeviceName("OracleProxy")
	for _, row := range rows {
		if row.Alias() == "OracleProxy" || row.InterfaceGUID == *expected { return false, nil }
	}
	return true, nil
}

'''
DORMANT_RECOVERY = '''// RecoverDormantOracleAdapter handles only a dead creator's unconfigured
// standby orphan while the authenticated parent is persistently Off. Unlike
// guarded recovery it never removes addresses, routes or DNS. Native snapshots
// must prove only Windows-generated IPv6 link-local state remains before a
// fresh Create is attempted. A Down row alone never permits recovery.
func RecoverDormantOracleAdapter(value uint64) error {
	oracleAdapterMutex.Lock()
	defer oracleAdapterMutex.Unlock()
	if value == 0 || oraclePreparedAdapter != nil { return fmt.Errorf("ORPHAN_IDENTITY_FAILED") }
	luid := winipcfg.LUID(value)
	if err := verifyOracleDormantEmpty(luid); err != nil { return err }
	// A live/existing device or packet session must cause Create to collide.
	// Never open/adopt it. Only this successful fresh Create grants a creator
	// handle that this helper may close; no packet session is started here.
	if err := verifyOracleRecoveryIdentity(luid); err != nil { return err }
	created, err := wintun.CreateAdapter("OracleProxy", TunnelType, generateGUIDByDeviceName("OracleProxy"))
	if err != nil { return fmt.Errorf("DORMANT_RECREATE_FAILED") }
	fresh := winipcfg.LUID(created.LUID())
	err = verifyOracleDormantEmpty(fresh)
	// Always close our own fresh creator, including on a failed native audit.
	// WintunCloseAdapter has void ABI; inspect the native table independently.
	created.Close()
	if err != nil { return err }
	for attempt := 0; attempt < 30; attempt++ {
		absent, queryErr := oracleRecoveryAbsent()
		if queryErr != nil { return fmt.Errorf("DORMANT_VERIFY_FAILED") }
		if absent { return nil }
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("DORMANT_VERIFY_FAILED")
}

func verifyOracleDormantEmpty(luid winipcfg.LUID) error {
	if err := verifyOracleRecoveryIdentity(luid); err != nil { return err }
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("DORMANT_IP_QUERY_FAILED") }
	// Windows creates IPv6 link-local metadata even for a fresh sessionless
	// adapter. Admit only native automatic origins and /64, never manual,
	// unknown, IPv4, or routable addresses. Keep the exact audited addresses
	// and prefixes so an unrelated link-local route cannot grant recovery.
	automaticAddresses := make(map[netip.Addr]bool)
	automaticPrefixes := make(map[netip.Prefix]bool)
	for _, entry := range addresses {
		if entry.InterfaceLUID != luid { continue }
		// Interface membership comes only from the native exact LUID. Compare
		// IPv6 bytes without a textual scope; never derive ownership from zone.
		address := entry.Address.Addr().WithZone("")
		if entry.Address.Family != windows.AF_INET6 || !address.Is6() || !address.IsLinkLocalUnicast() ||
			entry.PrefixOrigin != winipcfg.PrefixOriginWellKnown ||
			(entry.SuffixOrigin != winipcfg.SuffixOriginLinkLayerAddress && entry.SuffixOrigin != winipcfg.SuffixOriginRandom) ||
			entry.OnLinkPrefixLength != 64 || automaticAddresses[address] {
			return fmt.Errorf("DORMANT_IP_NOT_EMPTY")
		}
		automaticAddresses[address] = true
		automaticPrefixes[netip.PrefixFrom(address, 64).Masked()] = true
	}
	if err = verifyOracleRecoveryIdentity(luid); err != nil { return err }
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil { return fmt.Errorf("DORMANT_ROUTE_QUERY_FAILED") }
	for _, entry := range routes {
		if entry.InterfaceLUID != luid { continue }
		prefix := entry.DestinationPrefix.Prefix()
		nextHop := entry.NextHop.Addr().WithZone("")
		// MIB_IPPROTO_LOCAL is native RouteProtocolLocal, not NetMgmt/manual.
		// Require a valid IPv6 on-link next-hop and an exact audited /64 or
		// /128. ff00::/8 is Windows' automatic interface multicast route.
		if entry.NextHop.Family != windows.AF_INET6 || !nextHop.Is6() || !nextHop.IsUnspecified() ||
			entry.Protocol != winipcfg.RouteProtocolLocal || !prefix.IsValid() || !prefix.Addr().Is6() ||
			(!automaticPrefixes[prefix] && !(prefix.Bits() == 128 && automaticAddresses[prefix.Addr()]) &&
				prefix != netip.PrefixFrom(netip.AddrFrom16([16]byte{0xff}), 8)) {
			return fmt.Errorf("DORMANT_ROUTE_NOT_EMPTY")
		}
	}
	if err = verifyOracleRecoveryIdentity(luid); err != nil { return err }
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAll)
	if err != nil { return fmt.Errorf("DORMANT_DNS_QUERY_FAILED") }
	matches := 0
	for _, entry := range adapters {
		if entry == nil { return fmt.Errorf("DORMANT_DNS_QUERY_FAILED") }
		if entry.LUID != luid { continue }
		matches++
		if entry.OperStatus != winipcfg.IfOperStatusDown || entry.FriendlyName() != "OracleProxy" ||
			entry.Description() != "sing-tun Tunnel" || entry.IfType != winipcfg.IfTypePropVirtual {
			return fmt.Errorf("ORPHAN_IDENTITY_FAILED")
		}
		if entry.FirstDNSServerAddress != nil || entry.DNSSuffix() != "" || entry.FirstDNSSuffix != nil {
			return fmt.Errorf("DORMANT_DNS_NOT_EMPTY")
		}
	}
	// A successful full native snapshot with no matching LUID proves no current
	// effective DNS association. This is not a claim about persisted registry
	// settings. Duplicate entries are ambiguous and must not grant recovery.
	if matches > 1 { return fmt.Errorf("DORMANT_DNS_QUERY_FAILED") }
	return verifyOracleRecoveryIdentity(luid)
}

'''
BODY = '''func addRouteList(luid winipcfg.LUID, destinations []netip.Prefix, gateway4 netip.Addr, gateway6 netip.Addr, metric uint32) error {
	row := winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	row.Metric = metric
	nextHop4 := row.NextHop
	nextHop6 := row.NextHop
	if gateway4.IsValid() {
		nextHop4.SetAddr(gateway4)
	}
	if gateway6.IsValid() {
		nextHop6.SetAddr(gateway6)
	}
	rows := make([]winipcfg.MibIPforwardRow2, len(destinations))
	for i, destination := range destinations {
		rows[i] = row
		if err := rows[i].DestinationPrefix.SetPrefix(destination); err != nil {
			return err
		}
		if destination.Addr().Is4() {
			rows[i].NextHop = nextHop4
		} else {
			rows[i].NextHop = nextHop6
		}
	}
	// Oracle Proxy modification: bound Windows route notifications to four
	// concurrent calls. In particular, excluding one relay /32 produces many
	// prefixes. Each worker owns its row and error slot; activation waits for
	// EVERY call, including when one fails, before adapter teardown can run.
	errs := make([]error, len(rows))
	var pending sync.WaitGroup
	workers := make(chan struct{}, 4)
	for i := range rows {
		workers <- struct{}{}
		pending.Add(1)
		go func(i int) {
			defer pending.Done()
			defer func() { <-workers }()
			errs[i] = rows[i].Create()
		}(i)
	}
	pending.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

'''


def patched(original):
    if hashlib.sha256(original).hexdigest() != PREIMAGE:
        raise ValueError('PINNED_WINDOWS_TUN_SOURCE_REQUIRED')
    source = original.decode('utf-8')
    start = source.index('\tadapter, err := wintun.CreateAdapter(options.Name,')
    end = source.index('\n\tnativeTun :=', start)
    source = source[:start] + '\tadapter, err := openOracleAdapter(options.Name)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n' + source[end:]
    source = source.replace('func New(options Options)', CACHE + RECOVERY + DORMANT_RECOVERY + 'func New(options Options)', 1)
    old = '\t\tt.session.End()\n\t\tt.adapter.Close()'
    new = '''\t\tt.session.End()
		if t.options.Name == "OracleProxy" {
			err = t.prepareOracleAdapter()
			if err != nil {
				t.adapter.Close()
			}
		} else {
			t.adapter.Close()
		}'''
    if source.count(old) != 1:
        raise ValueError('PINNED_ADAPTER_CLOSE_REQUIRED')
    source = source.replace(old, new, 1)
    start = source.index('func addRouteList(')
    end = source.index('func generateGUIDByDeviceName(', start)
    return (source[:start] + BODY + source[end:]).encode('utf-8')


def main():
    if sys.argv[1:]:
        raise ValueError('NO_ARGUMENTS_SUPPORTED')
    TARGET.write_bytes(patched(TARGET.read_bytes()))
    print('PINNED_WINDOWS_ROUTE_CREATION_PATCH=PASS')


if __name__ == '__main__':
    main()
