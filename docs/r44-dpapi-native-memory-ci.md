# R44 — Disposable DPAPI-to-native-memory WireGuardNT proof

G6's original test generates a raw temporary binary key bundle and passes
it to a native C driver adapter. R44 adds a **separate allowlisted CI mode**:

1. Python's pinned cryptography package creates two fresh X25519 keypairs
   in process memory. Windows `CryptProtectData` (DPAPI LocalMachine,
   fixed CI-specific optional entropy, UI disabled) seals the 128-byte
   test bundle *before it is written to disk*.
2. The Windows script restricts the resulting `.dpapi` file ACL to the
   runner identity and LocalSystem. The corresponding 128-byte raw bundle
   must not exist.
3. A separate native executable checks the exact disposable GitHub
   Windows runner identity before accessing any native driver API.
4. It calls `CryptUnprotectData` into native process memory, checks the
   plaintext length, passes the keys through in-memory
   `WireGuardSetConfiguration` to two fixed localhost-only native peers,
   then erases intermediate native buffers. There is **no WireGuard
   plaintext configuration file** in this R44 driver test.
5. Genuine driver-reported handshakes must succeed. The test closes its
   adapters, requests removal of only its own test driver on the
   disposable VM, deletes the DPAPI bundle, and checks IPv4/IPv6 default
   route, DNS and Windows Firewall baselines.
6. Unauthorized execution of both the generator and native executable
   is exercised as a negative test.

## Do not infer production key safety

The `wgnt-r44-dpapi-native.exe` and its key generator are **CI-only**
tools, not the shipped manager or a SYSTEM service. The DPAPI
LocalMachine scope is not a security principal boundary; ACLs, service
identity and Windows key-management are still necessary. Python and the
C runtime may produce transient in-memory copies beyond guaranteed
zeroization. Test-only keys are never production keys.

The installed manager remains wired to `UnavailableProductionKernel`.
R38's distinct SCM tunnel.dll flow still uses a protected temporary
plaintext configuration file while that service is active. R44 proves
native WireGuardNT can accept private configuration in memory, not yet
that this CI route has been safely integrated into SYSTEM control,
whole-device WFP, safe Off, installer or UU compatibility.

No modification of Oracle, WireSock, UU or a user Windows network.
Issue #34 remains the release blocker.
