# R81 — default-disabled, compile-time separated experimental field scope and protected expiring lease

R80 completed real Windows native SCM service `LoadLibraryEx` preflight enforcement for fixed dual-stack localhost CI profiles, including a config+manifest jointly repinned default-route negative test. **That default lab mode cannot connect to an external public Oracle endpoint**. R81 begins a carefully isolated prospective field-only profile, without starting any tunnel or changing Windows/Oracle networks.

## Build separation

- In `OracleProxy.WireGuardHost.csproj`, `EnableAttendedFieldTrial` defaults to `false` and must be exactly `true` or `false`. The ordinary/default build entirely excludes `FieldTrialRuntimeLease.cs`, rejects `--ci-r81-field-self-test` and rejects SCM profile `lab-field`. No existing default production manager behavior is changed.
- An explicitly built **diagnostic-only** service-host may recognize the exact `lab-field` profile. Real service execution still requires the **LocalSystem Session 0** gate in Program.Main, existing pinned upstream WireGuardNT driver Authenticode/SHA-256 provenance, EngineBundle config+binary hash manifest and Admin/SYSTEM-only installation ACLs, followed by `NativeLabInnerScopeGate` dispatch to `FieldTrialRuntimeLease.Require` **before native LoadLibraryEx**. No installer or native field build is distributed or run on a real PC by this work.
- The field config must contain exactly one Interface/Peer, private `10.77.72.2/32`, `AllowedIPs` only `10.77.72.1/32`, canonical nonzero 32-byte key material, port 51828, keepalive 25, an exact parseable global-unicast IPv4 Endpoint, and absolutely no DNS, scripts, IPv6, route widening or extra peer. This is still only narrow IPv4 tunnel scope, not a full-device proxy or WFP leak closure.
- A separate fixed `ProgramData/OracleProxyLab/config/lab-field-lease.json` must have protected Admin/SYSTEM-only NTFS ACLs, exact schema 1, explicit target/public server key and SHA-256 matching the config bytes, issued/expiry UTC strings, a remaining duration of 1–20 minutes and issuance no more than 5 minutes ago. Duplicate/unknown JSON properties and older/expired leases are denied. For real use, the actual operator approval procedure must be separately confirmed; a boolean inside a locally writable file is **not** cryptographically authenticated consent.

## Disposable Windows CI

- Compile a normal release host with field code excluded. Confirm it returns refusal for both field test command and service profile.
- Compile a separate test host with the flag. Run synthetic in-memory hostile profile mutations (default routes, wrong endpoint/port, broad CIDR, DNS/hooks, expired lease, documentation/private/loopback address refusals); check non-SYSTEM service start is denied.
- Stage a synthetic fixture in a fresh Admin/SYSTEM-only protected directory with a fake private key and `8.8.8.8` as a **never-contacted parser fixture**. Synthetic `operator_confirmation_recorded=true` proves only JSON parsing, **not real-world user permission**.
- Invoke only the read-only host lease check, mutate expiry to the past and verify refusal, restore protected bytes, reject a spoofed environment; always remove exactly owned files and assert no native SCM service or tunnel route exists.

## Important limitations before a physical public-native handshake

**R81 is not authorization to deploy the diagnostic build, install any service/driver, attach an Oracle NSG, start UDP51828, or use `WireSock`/UU alongside an untested native tunnel.** It does not provide a durable system scheduler/Off watchdog in the field build, reboot-safe cleanup, signed installer, trustworthy approval signature, DPAPI private-key vault, real public peer identity or external IPv6/DNS WFP leak-proof. The record of R71 user-observed normal UU and ordinary Internet after a read-only diagnostic is not a native VPN compatibility test. The default `UnavailableProductionKernel` and issue #34 remain the GA blockers.

Next required action: on a disposable Windows runner, independently verify that an attended field lease can be provisioned from R72/R76 keys and an explicit 20-minute OS-owned recovery task **before** authorizing any field native SCM start. Future physical host and production Oracle modifications remain separately consent-gated.
