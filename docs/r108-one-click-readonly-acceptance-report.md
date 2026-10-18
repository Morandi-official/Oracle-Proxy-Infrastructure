# R108: one-click sanitized Windows acceptance report (nonmutating Alpha)

## User proposal accepted with safety boundaries

The objective is to add a visible **一键检查并导出报告** button to the actual Windows GUI. It collects a consistent, machine-readable status/evidence matrix so the user can provide results from a later, separately recoverable Windows test machine. A report is produced only after user interaction and saved locally by the user; no report, key or telemetry is automatically sent to GitHub, Oracle or a service.

**It does not turn the current preview into a functional WireGuard/WFP full-device VPN.** The production executable must keep the R83 `UnavailableProductionKernel` and deny connect/disconnect. An untested kernel kill switch must never be advertised as protecting a remote-control PC, even if upstream WireGuard/WireSock code is reused.

## Tested functions and evidence classes

The report uses Windows native, read-only API observations already provided by R54 and an authenticated/SCM PID-bound manager Status pipe (if present). It may record:
- Count of candidate active Ethernet/Wi-Fi interfaces and whether IPv4/IPv6 default route candidates exist; **not** their addresses, interface indexes, MACs, gateways, DNS or routes.
- Allowlisted service **states** for existing WireSock and WireGuard management services and a boolean UU process-name presence; **not** PID, executable path, service config, signatures, sessions or account.
- Whether the known read-only manager Status pipe is OS identity-checked; a missing/rogue pipe is recorded only as `false`, never as tunnel status.

The following independent proof gates are ALWAYS `NOT_TESTED` or `NOT_VERIFIED` in R108 regardless of those observations: actual different-host WireGuard authentication, trusted signed engine, system-owned physical IPv4/IPv6/TCP/UDP/DNS WFP leak proof, underlay packet capture, stale handshake and crash, Windows reboot/prelogin, explicit safe-Off, real UU remote continuity and binary process identity, trusted signed installer/updater/rollback. The report includes `ga_authorized=false` and `safe_to_replace_wiresock=false` and `BLOCKED_R83`.

A green selftest is source/negative-testing evidence only, not proof of a VPN. No active public network probe, raw network capture, route/DNS/firewall change, PowerShell execution, service start/stop, admin request, or automatic live WFP mutation occurs.

## Manual GUI steps for a future supervised test

1. Only launch an explicitly vetted, unsigned read-only preview on a **noncritical locally recoverable PC**; do not disable SmartScreen, script execution policy or AV if Windows rejects it.
2. Press **一键检查并导出报告**. Choose a local `.json` destination. No automatic upload occurs.
3. Review the JSON yourself for sensitivity, then share it in private project chat if appropriate. Avoid sharing raw packets, host keys, SSH/WireGuard private keys, full route tables or real Oracle server IP.
4. Later versions may add a separate high-risk “real sandbox test” workflow which MUST require dedicated authorization, physical/out-of-band rollback, 60-second restore timeouts, post-connect packet capture, crash/reboot proof, exact-owned policy cleanup, and UU-process continuity. Such a button is not present in R108 and must not be activated on an indispensable UU host without these prerequisites.

## CI verification and artifacts

The existing GitHub-hosted Windows `windows-client-preview.yml` builds a read-only self-contained EXE, executes `--acceptance-report-self-test` with hostile status fields, verifies mandatory tests remain unverified, and continues to upload the separately labelled unsigned preview ZIP. The production/main-source-safety workflow also tests the report while confirming no WireGuard DLL, privileged manager or signed installer is inadvertently shipped.

This gives a working acceptance-report feature now, while true full-device VPN/WFP remains an independent development task and GA Issue #34 stays OPEN.
