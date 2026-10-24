"""Pin the owned WireGuard TCP policy change; source accompanies the build."""
import hashlib
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'core/vendor/github.com/sagernet/sing-box/transport/wireguard/device_stack.go'
PREIMAGE='c93147e90f93595fd6d1725d9daaa34bc3aad251367779c9d5548b4b36523cb9'
ANCHOR='\ttunDevice.stack = ipStack\n'
PATCH='''\t// Oracle Proxy: use CUBIC on the actual userspace TCP endpoint. The
	// server kernel only forwards this traffic; changing its TCP CC cannot
	// tune these client-owned sessions. Retain upstream buffer/window sizes.
	congestion := tcpip.CongestionControlOption("cubic")
	if optionErr := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &congestion); optionErr != nil {
		ipStack.Close()
		return nil, gonet.TranslateNetstackError(optionErr)
	}
'''

def patched(body):
    if hashlib.sha256(body).hexdigest()!=PREIMAGE:raise ValueError('PINNED_WIREGUARD_TCP_SOURCE_REQUIRED')
    text=body.decode()
    if text.count(ANCHOR)!=1:raise ValueError('UNIQUE_TCP_POLICY_LOCATION_REQUIRED')
    return text.replace(ANCHOR,PATCH+ANCHOR).encode()


def main():
    if sys.argv[1:]:raise ValueError('NO_ARGUMENTS_SUPPORTED')
    TARGET.write_bytes(patched(TARGET.read_bytes()))
    test=Path(__file__).with_name('wireguard-tcp-policy_test.go')
    TARGET.with_name('oracle_tcp_policy_test.go').write_bytes(test.read_bytes())
    print('PINNED_WIREGUARD_CUBIC_POLICY_PATCH=PASS')

if __name__=='__main__':main()
