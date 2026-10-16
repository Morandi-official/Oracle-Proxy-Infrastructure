# R56 — Opt-in Windows GUI connects and disconnects R55 SSH SOCKS5

## Grounded acceptance evidence from 2026-10-16

The user reported real Windows PowerShell / Edge tests of R55 using
their already-configured Oracle Ubuntu 22.04 ARM64 host. The original
R55 console reported `R55_LOCAL_SOCKS5_LISTENING: 127.0.0.1:10880`.
Two independent external HTTPS IP-echo endpoints returned the matching
Oracle public exit address with HTTP 200 and curl exit code 0;
reported total times were approximately 1.26s and 1.50s. The user
also confirmed that **a separately configured Microsoft Edge SOCKS5
instance showed the matching Oracle IP and loaded Wikipedia**.

These are **operator-reported live application-level successes**, not
packet-capture proof of system-wide route protection or evidence that
R56's new GUI has been tested physically. Do not commit the user's
private-key filename, SSH host, or credentials as application defaults.

## What R56 adds

A separate portable WinForms executable
`OracleProxy.AppSocks5.GUI.Experimental.exe` contains:

- Explicit, manual SSH host / username / port / private key textboxes,
  with a file picker. No embedded private key or production host.
  Nothing connects until the user presses **连接应用级代理**.
- Local check for an existing SSH private key and
  `%USERPROFILE%\.ssh\known_hosts` with strict R55
  `StrictHostKeyChecking=yes`. Unknown hosts are **not** silently
  accepted. SSH arguments use `ProcessStartInfo.ArgumentList`,
  not command-line string concatenation.
- The **unchanged R55 SSH experiment binary** is distributed alongside
  the GUI and handles all actual OpenSSH SOCKS5 forwarding, fixed local
  `127.0.0.1:10880` listener, exit validation and strict host policy.
  R56 only manages **that directly spawned process**.
- A Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
  owns the GUI-launched R55 child. R55 itself owns its OpenSSH child
  with the same OS mechanism. The nested ownership chain allows GUI
  disconnect/window close/crash to terminate **its own** helper and SSH
  (not other existing WireSock/UU/SSH processes). If job assignment
  fails, connecting fails closed.
- Disabled duplicate Connect, explicit Disconnect, asynchronous
  startup with 16-second timeout, exact-match R55 local-listener
  readiness marker, background process-exit monitoring. No false claim
  that listener readiness proves Oracle exit routing.
- Closing the GUI immediately disposes the job; there is **no
  autostart, Windows service or persistent install**. The GUI neither
  opens Edge nor modifies any browser settings by itself.

## GitHub CI limits and actions

Disposable Windows CI builds R55 and R56 as two self-contained unsigned
win-x64 EXEs and only ships those, `READ_ME_FIRST.txt` and a hash
manifest. It executes both tools' offline input-policy checks and
Win32 child job termination checks with a temporary loopback test
process. Independently checks no SOCKS listener appeared and verifies
default routes, DNS server lists and firewall rule counts unchanged.
No Oracle SSH keys are available to CI; no network-facing Oracle SSH
connection occurs. Windows GUI appearance, key-picker UX, and R56
physical disconnect / reconnection / power-off behavior **remain
unverified** until supervised acceptance.

## Instructions when user returns to the physical PC

1. Keep the existing production WireSock and UU remote-control setup
   untouched. On a machine accessible without relying on the proxy,
   download the R56 unsigned CI artifact from the successful GitHub
   Actions run. If Windows security rejects the unsigned binary,
   **stop**; don't disable SmartScreen, antivirus or corporate policy.
2. Extract the entire ZIP. Inspect `READ_ME_FIRST.txt` and
   `build-manifest.json` (SHA-256 of both EXEs).
3. Run `OracleProxy.AppSocks5.GUI.Experimental.exe` without elevation.
   Supply the known Oracle SSH host, user, SSH port, and **select**
   the already-owned private-key file locally. Never paste key
   material in a chat. Do not change Windows system proxy.
4. Click **连接应用级代理**. When the app reports the local listener,
   launch Edge as a separate temporary profile (per earlier R55
   acceptance recipe) with SOCKS5 `127.0.0.1:10880` and remote
   DNS; verify one HTTPS IP-echo and one ordinary webpage manually.
   Never call local-listener detection a confirmed proxy exit.
5. Close the separate Edge test instance, then click
   **断开代理**. Confirm the R56-owned localhost port closes and
   that ordinary direct Edge/UU remain available. Reconnect only
   if independent recovery is available.
6. Close GUI; it must never change Windows global proxy, DNS,
   firewall, route, UU, Oracle configuration, or stop a separately
   started R55 console session.

## Non-goals

**This is NOT a working WireGuard replacement or full-device VPN.**
There is no per-app WFP leakproof policy, no full IPv4/IPv6/DNS
coverage, no system-wide traffic capture and no UU traffic
exemption engine. R56 is only a front-end for R55's existing
application-scoped SSH SOCKS5 proxy. GA #34 remains OPEN.
