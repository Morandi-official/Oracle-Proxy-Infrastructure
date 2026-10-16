# R47 — true LocalSystem -> native WireGuardNT DPAPI memory lab bridge

R44 demonstrated a real in-memory Windows DPAPI-to-WireGuardNT handshake
in an elevated disposable CI process, with no plaintext input file.
R45 separately demonstrated DPAPI 32-byte key leases inside an actual
LocalSystem SCM service. R47 deliberately joins **these** paths for two
new ephemeral peers on a single disposable GitHub Windows VM.

The R47-only manager service is built with
`EnableDisposableLabControls=true`; the default release binary removes
all code and switches for the test. After native IP Helper/WFP read-only
preflight, the true LocalSystem Session-0 SCM manager launches the
fixed precompiled R44 native child in a bounded worker.

The child reads only a DPAPI LocalMachine-protected ciphertext from an
explicit, protected `ProgramData\OracleProxyR47CiOnly` test directory,
uses the pinned official WireGuardNT native DLL, unseals in process RAM,
calls the real `WireGuardSetConfiguration` driver API on two fixed
localhost-only, narrow /32 lab adapters, and confirms two independent
driver-reported handshakes. The parent emits only one short PASS/FAIL
receipt (never keys, config, IP or user identity). It never accepts peer
names, endpoints, paths or native process arguments from a GUI or IPC.

The CI job protects a newly created lab directory with Admin/SYSTEM-only
DACL, requires the official signed DLL and exact binary/ciphertext
hash copy, installs a demand-start LocalSystem manager and waits for
the receipt. It checks that authenticated status-only IPC still denies
mutating requests. After shutdown it deletes only the exact CI-owned
service and protected stage, removes encrypted test keys, and verifies
default IPv4/IPv6 routes, DNS and Windows Firewall state are restored.

## Strict non-claims

This is **not** a production VPN service or a full-device kill switch.
The native worker is child of SYSTEM instead of an in-process persistent
production adapter. The Config API is used only for fixed synthetic peers
with localhost UDP. Driver/WFP crash recovery is not proven, and a force-
terminated worker can leave temporary adapters until the disposable runner
is destroyed. The DPAPI LocalMachine scope alone is not a production
identity barrier. No Oracle account, real key, WireSock, UU or personal PC
is accessed; issue #34 remains the launch blocker. The normal service
still has `UnavailableProductionKernel` and cannot connect or release
actual production WFP rules.
