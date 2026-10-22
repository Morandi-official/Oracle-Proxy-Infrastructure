"""Apply the owned, exact-preimage Windows route creation optimization.

No prefix, gateway, metric or policy changes. All route creations must complete
before activation; an error still tears down the newly created owned adapter.
The actual modified dependency source is included in corresponding-source.zip.
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
	if err != nil && errors.Is(err, os.ErrExist) {
		return wintun.OpenAdapter(name)
	}
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

func (t *NativeTun) prepareOracleAdapter() error {
	luid := winipcfg.LUID(t.adapter.LUID())
	// Scope is closed while the parent's persistent fail-close guard is still
	// active. Remove addresses, routes and DNS before acknowledging standby.
	if err := luid.FlushIPAddresses(windows.AF_UNSPEC); err != nil {
		return err
	}
	if err := luid.FlushRoutes(windows.AF_UNSPEC); err != nil {
		return err
	}
	if err := luid.FlushDNS(windows.AF_INET); err != nil {
		return err
	}
	if err := luid.FlushDNS(windows.AF_INET6); err != nil {
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
    source = source.replace('func New(options Options)', CACHE + 'func New(options Options)', 1)
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
