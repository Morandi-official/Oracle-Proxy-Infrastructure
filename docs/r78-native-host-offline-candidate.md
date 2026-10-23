# R78 — service-host refuses untrusted field profiles before privileged native activation (CI-only)

R77 successfully created and deleted one protected plaintext synthetic WireGuard candidate under a Windows Admin/System-only temporary directory. R78 adds the next separated precondition: **the actual repository Windows service-host executable** must independently audit that staged profile with the existing native host NTFS ACL gate, **without loading WireGuard, registering SCM or changing any network policy**.

## Exact evidence scope

- Adds `FieldCandidateScopeReview` to the service-host assembly. `--ci-r78-field-scope-review` requires a disposable Windows GitHub runner, explicit R77/R78 CI env gate and authenticated admin token. It uses only the fixed `ProgramData/OracleProxyR77Only/.r77-owned` and `lab-peer-a.conf` paths; refuses missing or unsigned/unowned staging markers and files.
- Uses the actual `ConfigAclGate.RequireProtectedLabSealedFile` read-only security check on the protected marker and candidate. R77 staging now converts both marker and config to independently protected Admin/System-only ACLs. No ACL is changed by the native host during review.
- Validates one exact interface and peer, correct canonical 32-byte nonzero WireGuard keys, `Address = 10.77.72.2/32`, `AllowedIPs = 10.77.72.1/32`, no DNS or scripts/extra fields, no IPv6/default route, and a **synthetic never-contacted** external-looking endpoint `8.8.8.8:51828` used by the R77 test fixture. This is intentionally **not** a dynamic real Oracle endpoint policy and is not a way to send packets to that address.
- Offline C# self-tests reject default/widened routes, renamed interfaces, unexpected endpoints, DNS hooks, extra peer sections, bad base64 keys and newline contamination. All secret-bearing data stays in process memory and is never printed or uploaded. No CLI accepted by this change can start or stop a tunnel.
- Windows CI verifies early refuse without R77 fixture, bad environment refusal, successful real service-host inspection of protected R77 candidate, then runs the always-cleanup stage and confirms no native SCM service, new route or plaintext temporary file remains.

## Security limitations and next gate

R78 does **not** provide actual X25519 reciprocal identity validation inside the C# host (R76 separately tests private-public matching when creating the candidate). The tested fixture endpoint is synthetic, not a real public host. R78 does **not** perform a native service start, prove a cross-host WireGuard handshake, persist a watchdog after reboot or isolate application-wide WFP/IPv6/DNS packets. The service-host's CI audit command is not a production authorization, secure key vault, signed installer, field-ready per-peer loader or real user-side tool.

R71 physical read-only diagnostics and post-test ordinary Internet and UU reports were successful. However, **no new real Windows/OEM driver, Oracle NSG, public UDP listener, WireSock, UU or production wg0 modification is authorized here**. GA blocker #34 and the compiled `UnavailableProductionKernel` remain unchanged.
