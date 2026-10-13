# Security policy and public-repository checklist

This repository is **public source code**. It must NEVER become the location of
Oracle server credentials, WireGuard private keys, SSH private keys, plaintext
client configuration files, production snapshots, or personal device IP logs.

## Boundaries

- The prototype API and dashboard are **read-only**.
- Run the dashboard exclusively bound to `127.0.0.1`. For remote access, use an SSH tunnel with authentication; never open port 8765 in an Oracle security list or firewall.
- HTTP Basic authentication is deliberately limited to local/SSH-tunnel demonstration. It is **not** production-grade web login or multiuser authentication. Real deployments will need sessions, CSRF protections, RBAC, HTTPS and audit logging.
- No public endpoints may return `PrivateKey`, endpoint IP, private peer configuration, or raw `wg show ... dump`.
- The collector must not be run by the API process or offered broad `sudo` access. A reviewed service/group permission model is required before deployment.
- A WireGuard handshake is **not** proof a device is currently online.
- Dashboard demonstrations use synthetic data and do not access the Oracle server.

## Before any public Git push

1. Inspect `git status` and `git diff --cached`.
2. Keep `.env`, `*.key`, `*.conf`, `*.pem`, `*.pfx`, exported subscription files, login cookies and credentials out of commits.
3. Never paste GitHub access tokens or personal device public IPs into workflow logs, issues, or PRs.
4. When in doubt, stop and review before pushing. `.gitignore` alone does not stop `git add -f`.
5. If a real secret is accidentally committed, revoke/rotate it immediately; simply deleting it from the next commit does not remove it from Git history.

## Reporting vulnerabilities

Do not post passwords, key files, live configuration, or exploit logs in public GitHub issues. Use GitHub's private vulnerability reporting feature if enabled on the repository. Otherwise contact the maintainer through an agreed private channel first.

## Licensing

Public visibility does not grant a general license to copy or redistribute the source. A license will be selected by the repository owner after reviewing dependencies and the intended commercial/noncommercial use. WireSock SDK is not included in this repository.
