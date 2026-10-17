# R76 — offline candidate native WireGuardNT profile for ONE external peer

R71 actual physical Windows **read-only** diagnostic and independent user-confirmed normal Internet/UU after its run are complete. R68 separately proved a public WireGuard tunnel only with the **official** Windows client. R69/R70/R73/R74/R75 proved genuine native self-developed management and WireGuardNT interaction on a **single disposable Windows runner**, not an external public peer. None of those results enable a production Windows VPN client.

## What R76 does

This change adds only the importable Python pure function `render_in_memory(proposal_bytes, ephemeral_client_private_bytes)`. The function:

- Requires a **fresh valid R72 metadata proposal**: exact `10.77.72.2/32` local client address, exact single `10.77.72.1/32` server-only AllowedIPs, explicit real public IPv4 server endpoint on UDP51828, a freshly observed distinct public client IPv4, different server/client X25519 public keys, expiry no longer than 20 minutes, DNS/default-route/firewall/driver preserve policies, and explicit statement that further operator authorization is required.
- Uses real X25519 public-key derivation to compare the provided ephemeral client private key against the client's proposal public key before generating any candidate text. Mismatched, empty and invalid secret identities are rejected.
- Produces exactly one `Interface` and exactly one `Peer` in memory, with fixed `AllowedIPs = 10.77.72.1/32`, `Address = 10.77.72.2/32`, `PersistentKeepalive = 25`, exact validated public endpoint and **no DNS, hooks, IPv6, route widening or default route**.
- Independently rechecks the finished output's exact field ordering/grammar and denies changed CIDRs, extra DNS, extra peers, different port or Windows line-ending contamination.
- Provides no CLI configuration writer, driver installation, service startup, network probe, private-key logger, authorizing token or output artifact. Running this module as a CLI always exits with code 2.

CI executes positive and adversarial tests with **synthetic fixture key bytes**, not user keys. Windows and Ubuntu runners test both matching and mismatched X25519 identities and multiple illegal injection patterns. Tests never print a secret-bearing candidate profile or upload it as an artifact.

## What R76 does NOT prove

The function is NOT a secure key store. The returned Python string contains a private key while in memory and is intentionally discarded after the test; future real clients require an independently reviewed DPAPI/Lsa/OS protection boundary and zeroization design. It is NOT linked to the actual Windows SCM tunnel start and has not connected to any public Oracle endpoint. A syntactically correct config does not prove the actual Windows OS routing remains narrow or any physical IPv6/DNS WFP leak behavior. R72's metadata digest is not permission to connect.

The next gate is a CI-only single-peer SCM integration that consumes ephemeral, protected, reviewed configuration under actual OS identity with independent time-limited, preferably reboot-persistent rollback. Only after that, fresh **separate user approvals** are needed to modify an Oracle temporary endpoint/OCI NSG and to run native service or driver tests on a physical Windows PC. Production `UnavailableProductionKernel` and Issue #34 remain unchanged.
