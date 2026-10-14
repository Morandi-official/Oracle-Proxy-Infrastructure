# R17 — disposable Windows DPAPI X25519 private key storage

This is a genuine **offline** Windows cryptography/NTFS integration test, not
production key management or a WireSock replacement.

- Uses Windows DPAPI LocalMachine to encrypt exactly 32 random X25519 secret
  bytes into a fixed, CI-owned file inside RUNNER_TEMP, never plaintext.
- Requires both parent directory and key-file NTFS owner/ACL allow access
  only to SYSTEM or Administrators, rejects inherited or world-readable
  permissions, symlinks and wrong paths.
- Tests cross-instance decryption on the same Windows runner, rejects
  ciphertext corruption, rejects repeated creation, performs explicit owned
  deletion and zeros temporary secret arrays.
- Refuses invocation outside a disposable, GitHub-hosted Windows runner.

**Important limits:** DPAPI LocalMachine protection can also be used by
other accounts on the same host if ciphertext becomes readable; ACL isolation
and service identity are essential. A local administrator may still read or
decrypt these keys. The lab cannot prevent privileged ciphertext rollback,
prove key destruction on SSD sectors, or implement revoked peer-identity
rollover. The real WireGuard service still consumes a protected plaintext
configuration in the current synthetic test environment; this R17 vault
is deliberately **not wired into production tunnel startup**. A protected
decryption-to-native-memory approach needs separate design, service SID
binding, WFP safeguards and review before any functional Alpha.

No Oracle server, WireSock, UU, user files or default routes are touched.
The production installer and key rotation/revocation are still blocked by
issue #34.
