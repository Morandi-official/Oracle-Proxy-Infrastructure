# Oracle Proxy Infrastructure

An independent, security-first management plane for an existing Oracle Cloud WireGuard server.

**Status: Milestone 0 — read-only prototype. Do NOT expose this service on a public interface or deploy it to the live server yet.**

## Architecture

- Linux WireGuard (`wg0`) is the existing VPN dataplane. This repository does **not** replace WireGuard.
- A small privileged **collector** reads only non-secret WireGuard status using fixed `wg show` subcommands and produces a sanitized JSON snapshot.
- The unprivileged **FastAPI service** reads that JSON snapshot. It cannot alter peers or firewall rules and does not invoke `sudo` or `wg`.
- Future control plane: accounts, devices, per-peer traffic/quota, expiry, subscriptions, audit logs.
- Future clients: independent Windows/Android applications using legitimately licensed VPN engines; WireSock is an optional reference/integration candidate, not a hard dependency.

## Security guarantees and limitations

- API listens on `127.0.0.1` when started with the command below.
- `GET /health` is public but contains only generic status.
- `GET /api/v1/wireguard` requires a 32+ character bearer token.
- The response includes only an allowlist of fields. Peer public keys become SHA-256-derived pseudonymous identifiers; private keys, endpoint addresses and raw `wg` output are never included.
- Snapshot files are written atomically with mode `0600`. The future server deployment must provide a **specific read-only account/group permission arrangement** for the API process. Do not run the API as root.
- Fail closed: no valid token or unreadable snapshot means an error, not unrestricted access.
- This is **not** a complete security audit. Startup leak prevention, system-service routing, IPv6 protection and failures of client apps need separate tests.

## Local development (no Oracle server changes)

Requires Python 3.10+.

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
export ORACLE_PROXY_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export ORACLE_PROXY_SNAPSHOT_PATH="$PWD/tests/fixture_snapshot.json"
uvicorn app.main:app --host 127.0.0.1 --port 8765
```

On Windows PowerShell, activate the venv using `.venv\Scripts\Activate.ps1` and use `$env:...` for environment variables.

```bash
curl http://127.0.0.1:8765/health
curl -H "Authorization: Bearer $ORACLE_PROXY_API_TOKEN" http://127.0.0.1:8765/api/v1/wireguard
```

The fixture is **fabricated demo data**, not from the live server. The future collector command is:

```bash
python -m app.collector --interface wg0 --output /path/to/wg0.json
```

It requires OS authorization to read WireGuard status. Do **not** add broad sudo permissions or run the web API as root. We will design service accounts, systemd units and permissions during a later reviewed deployment step.

## Roadmap

1. **M0**: read-only snapshot + authenticated API + tests (this branch).
2. **M1**: local-only admin UI, accounts/auth sessions, explicit RBAC and audit trail.
3. **M2**: device enrollment with on-device private key generation, peer management with transactional rollback.
4. **M3**: data usage/quota accounting, expiry enforcement, per-device rate limits with Linux traffic control.
5. **M4**: subscription/config lifecycle and Windows/Android client prototypes.
6. **M5**: production security hardening: fail-closed policies, boot/restart tests, IPv6/DNS/WebRTC leak tests, backup and recovery.

Never commit SSH keys, WireGuard private keys or exported client configs.
