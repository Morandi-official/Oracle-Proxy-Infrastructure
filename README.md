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

## Read-only local dashboard (prototype)

Run the API as shown above, then open `http://127.0.0.1:8765/dashboard`.
The browser's HTTP Basic prompt uses username `admin` and password equal to your locally generated `ORACLE_PROXY_API_TOKEN` value. No token is stored in repository files, HTML, cookies or localStorage. Do not share the token or browse through plain-HTTP networks; run locally or through a properly secured SSH tunnel only. Closing the browser does not necessarily clear cached HTTP Basic credentials; use a private browsing session if appropriate.

The dashboard is read-only, does not auto-refresh or call third-party scripts, and only displays sanitized snapshot fields. The fixture is synthetic data. This is a preliminary view, **not a production-ready authenticated multiuser admin console**.

## CI and free Actions minutes

This project uses GitHub-hosted Ubuntu runners for short unit tests. To avoid running the same tests twice for every branch push with an open PR, the workflow triggers on PRs and on pushes to `main` only. Concurrent runs for the same PR cancel the older run. Every job has a 10-minute timeout.

View account-level consumption in GitHub account settings → **Billing and licensing** → **Usage**, filter to **Actions**, or inspect **Actions → workflow run → Usage** for one job. In **Budgets and alerts**, enable the included-usage 90% and 100% notifications. The GitHub Free personal allowance is 2,000 minutes/month for standard hosted jobs on private repositories; check your current plan directly in GitHub.

## 中文管理页面与 Windows 演示（不接触真实服务器）

在 Windows 的 PowerShell 中，进入克隆后的仓库目录，运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-demo.ps1
```

演示脚本会在 `backend/.venv` 创建独立 Python 环境、安装依赖并随机生成仅在本次进程中使用的演示密码。启动后在本机浏览器访问 `http://127.0.0.1:8765/dashboard`，输入终端显示的用户名和密码。**不要公开密码、截图或分享这次演示的登录凭据。** 结束时在 PowerShell 中按 `Ctrl+C`。

本演示使用 `backend/tests/fixture_snapshot.json` **虚构设备数据**。它不连接 Oracle、不修改 WireGuard/WireSock、不创建用户、不打开公网端口，也不执行任何 VPN 连接。首次安装 Python 依赖需要联网。

仓库现为 Public；上传任何真实服务器配置前，请先阅读 [SECURITY.md](SECURITY.md)。目前没有选定源码许可证，公开可见不代表其他人获得再分发的通用授权。
