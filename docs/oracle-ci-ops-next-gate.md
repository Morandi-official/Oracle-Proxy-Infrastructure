# Oracle GitHub Operations: verified boundary and next deployment gate

## Verified by operator, 2026-10-20

- Dedicated `oracle-ci-ops` private key authenticates as non-root `oracle-ci`, restricted by `authorized_keys` forced command.
- Existing `status` works. GitHub Actions `stage` wrote actual commit SHA `dde49fa04c6be1811e7b2576541117ed4be0cee4` to staging metadata.
- The former `oracle-ci-readonly` key authorization and obsolete status checker were removed, checked separately by the operator. The legacy RSA key for the working SSH proxy still works.
- The existing forced-command dispatcher at `/usr/local/bin/oracle-ci-gate` accepts **only** `status`, `stage <sha>`, and `rollback`. Staging SHA is **not a software deployment**.

## Planned next step (requires separate review/activation)

1. Keep GitHub `oracle-ops` environment, protected `main` branch and dedicated secrets. Avoid giving Actions unrestricted shell or `sudo`.
2. Prepare a restricted, versioned artifact mechanism for the unprivileged, read-only diagnostic component at `ops/oracle-ci/read-only-agent.sh`.
3. Require explicit operator inspection and **one-time** root-owned dispatcher upgrade through the existing separate human-admin SSH session. Version and back up only the owned dispatcher; test the original `status` and provide exact-file rollback.
4. Permit GitHub Actions to upload only a reviewed script with strict size/content hash limits. Run it only as `oracle-ci`; protect against path traversal/symlink and concurrent updates; retain previous version for rollback.
5. Prove delivery, read-only execution, idempotency, and actual rollback before considering any privileged configuration operation.

**Currently not authorized:** modifying `wg0`, production peers, OCI security lists, SSH server settings, firewall, routes, DNS, UU, WireSock, or installing a production VPN. Even an approved read-only component is NOT the signed Windows installer, complete server proxy or cross-network VPN acceptance.

No production server has been modified by this PR.
