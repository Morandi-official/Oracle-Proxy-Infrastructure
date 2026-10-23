# R1 — Windows protected VPN intent persistence (offline research prototype)

**Not a VPN, not a kill switch and not a production configuration store.**

This standalone .NET 8 x64 Windows application implements a small real
Windows DPAPI `LocalMachine` ciphertext store **only inside temporary
CI directories** and exercises real filesystem mutations there.
It does not query or modify the network, Windows services, Oracle, UU,
WireSock or registry.

## Why this is needed

The product must distinguish an authorized user explicitly selecting
`Disabled` from a tunnel accident, handshake stale, service crash or
unknown boot state. An unintended disconnect MUST NOT silently flip user
intent from `Enabled` to `Disabled`.

- A readable explicit `Enabled` record: intent stays Enabled no matter the
  simulated VPN connection status.
- A readable explicit `Disabled` record: direct mode may be considered
  by a *future* verified policy controller.
- Missing, unreadable, invalid, corrupted, truncated or oversized record:
  `UnknownFailClosed`. No automatic direct mode.
- Reinitializing a missing record directly to `Disabled` is disallowed.
  Actual initial Off provisioning would require an authenticated,
  separately audited authorization and recovery flow.
- A valid sequence increments revision but **does not resist rollback** to
  an older still-valid ciphertext. A local administrator or attacker who
  can access/replace the file and DPAPI machine keys remains privileged.

The application does **NOT** implement an OS-enforced WFP block and
`RequiresFailClosed=true` is **only a model obligation**. It does not
prevent IPv4/IPv6/DNS traffic or prove fail-closed on boot.

## Current test evidence

`OracleProxy.IntentLab.exe --offline-self-test` executes actual Windows
DPAPI encryption/decryption and temporary file operations, exercises
explicit On / authorized hypothetical Off, user-intent revision, real
ciphertext bit-flip corruption, zero-length, oversized, deleted and
reprovisioned record cases.

The test does not install a Windows service and has no CLI option to write
to the fixed production path. It is not called from the production GUI.

## Security gates before integration into any real privileged service

1. Move to a **separately protected** fixed `%ProgramData%` folder,
   with verified root/parent ACL owner, Service SID and protected DACL.
   Test symlink/reparse-point ancestry, directory replacement and file
   race handling. Current code does *not* fully address those attacks.
2. Enforce explicit user intent only through a dedicated authenticated,
   authorization-reviewed OS-token IPC request. Never accept a caller-
   supplied `authorized=true` Boolean as identity proof.
3. Add **anti-replay protection** for a saved old-but-valid Off ciphertext.
   DPAPI alone does NOT prevent ciphertext rollback.
4. Specify and test startup-before-network ordering, persistent
   WFP enforcement and crash/reboot restoration; these are not included.
5. Prove UU UDP P2P exception while physical IPv4/IPv6/DNS for other apps
   is blocked, with independent external capture and rollback console.
6. Perform all actual filter tests only in an isolated VM whose
   hypervisor console/snapshot restore is demonstrated first.

Until those gates are complete, the product must remain a clearly
labeled experimental/read-only preview.
