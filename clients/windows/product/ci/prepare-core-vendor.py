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
