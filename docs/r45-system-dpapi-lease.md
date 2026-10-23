# R45: Real LocalSystem DPAPI key lease integration in disposable Windows SCM

This stage adds a **real Windows LocalSystem process** exercise for an
ephemeral 32-byte WireGuard-size private-key lease.

The R45 workflow builds two independently separated manager binaries.
The ordinary release-mode binary excludes the CI-specific key-lease source,
DPAPI package dependency and CLI switches. The disposable
`EnableDisposableLabControls=true` manager accepts a fixed
`--manager-service --ci-system-dpapi-lease` SCM startup mode only when
running as LocalSystem in Session 0.

Before listening on any status/control pipe, the actual SCM service:

- Generates 32 random ephemeral key bytes in process memory.
- Protects them with Windows DPAPI LocalMachine using CI-specific entropy.
- Clears the original bytes before calling `Unprotect`.
- Checks the decrypted secret length and SHA-256 digest in constant time.
- Passes it through the fixed `ProtectedKeyLease`, then verifies zeroization.
- Corrupts a copy of ciphertext and requires DPAPI authentication failure.
- Clears all remaining managed arrays regardless of the result.

Non-SYSTEM processes must refuse the privileged self-test before key
generation or DPAPI decryption. The disposable workflow independently
installs and starts the actual LocalSystem SCM service, confirms only
STATUS_ONLY authenticated IPC, deletes the exact CI-created SCM registration
and verifies IPv4/IPv6 default routes, DNS settings and firewall rule
inventory remain unchanged.

**Security limitations:** This is ephemeral machine-local test material
only, not an actual VPN private key or a persistent production vault.
DPAPI LocalMachine does not isolate secrets from administrators or all local
machine principals by itself. Managed runtime and crypto APIs may create
transient copies beyond guaranteed zeroization. The manager's normal
`UnavailableProductionKernel` is untouched, no WireGuard adapter is
created, and no WFP rules are installed. R44's separate native test proves
`WireGuardSetConfiguration` can consume in-memory key material; R45 now
proves DPAPI lease verification actually runs inside a SYSTEM process.
They are **not yet an integrated production tunnel**.

No changes to the user's Windows, Oracle, WireSock or UU. The GA blocker
issue #34 remains open pending audited production WFP, release-safe Off,
signed installer, cross-network independent tests, and UU acceptance.
