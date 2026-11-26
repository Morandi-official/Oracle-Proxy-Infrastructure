"""Apply the pinned WireGuard TCP policy and connected UDP updates."""
import hashlib
from pathlib import Path
import subprocess
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
    stack=patched(TARGET.read_bytes())
    bind=TARGET.with_name('client_bind.go')
    if hashlib.sha256(bind.read_bytes()).hexdigest()!='d9d08284b63c18b3827115ef41ed5c034a5e84c40a43363c2baca170254b1e18':
        raise ValueError('PINNED_WIREGUARD_BIND_SOURCE_REQUIRED')
    here=Path(__file__).resolve().parent
    # Normalize checkout line endings before applying to go mod vendor's source.
    bind_patch=(here/'wireguard-connected-bind.patch').read_text(encoding='utf-8')
    subprocess.run(['git','apply','--no-index','--unidiff-zero','-'],input=bind_patch.encode(),cwd=ROOT.parents[2],check=True)
    TARGET.write_bytes(stack)
    test=Path(__file__).with_name('wireguard-tcp-policy_test.go')
    TARGET.with_name('oracle_tcp_policy_test.go').write_bytes(test.read_bytes())
    TARGET.with_name('oracle_connected_bind_test.go').write_bytes((here/'wireguard-connected-bind_test.go').read_bytes())
    print('PINNED_WIREGUARD_CUBIC_POLICY_PATCH=PASS')

if __name__=='__main__':main()
