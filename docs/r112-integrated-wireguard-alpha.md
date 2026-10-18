# R112 — Oracle Proxy self-contained WireGuard tunnel Alpha (no external official app)

## Deliverable boundary

The R111 opt-in Windows Alpha delegated tunnel install/uninstall to an already-installed official `wireguard.exe`, which **does not satisfy the user's requirement**. R112 replaces that dependency with a new standalone Windows GUI and service in the same `OracleProxy.WgAlpha.exe`, a project-built pinned upstream `tunnel.dll`, and an official signed/hash-pinned `wireguard.dll`. Windows users need **only the R112 zip contents**, not the WireGuard app, MSI, third-party tool or driver download. The signed WireGuardNT DLL may install its corresponding kernel driver through its documented API on an eligible supported Windows system during the attended tunnel run, subject to Windows driver enforcement.

This is experimental local administrator software with **real OS service and network-mutation capability**, not a fully tested replacement for WireSock, not an endorsed production installer, and not proof of cross-host Oracle access. The code intentionally does NOT bundle WireSock binaries, private keys, server configuration or a third-party driver copied from a running machine.

## How the product works

- The WinForms interface calls only a fixed, explicit native service name `WireGuardTunnel$OracleProxyAlphaTest`. No arbitrary service names, scripts, Windows security bypasses, or automated elevation.
- On a separate locally attended noncritical test Windows PC, explicitly select an independently obtained, trusted `OracleProxyAlphaTest.conf` test config. Config text validation refuses hook commands, routing override and unpaired /1 destinations or any /0 route. Running a split /1 full-route-like test **can still disrupt UU, DNS and ordinary networking**.
- The elevated GUI refuses an existing/unknown service or previous installation folder, verifies both embedded DLLs, creates fixed Admin/SYSTEM-only directories under Program Files and ProgramData, stages the exact executable + two DLLs and config, independently hashes the copies and installs a `DEMAND_START` LocalSystem SCM tunnel service with an unrestricted service SID and `Nsi/TcpIp` dependencies.
- When SCM invokes the program with the private `--service` switch, the program refuses non-SYSTEM or interactive session use, rejects foreign service ImagePath, unprotected ACLs and any modified DLL/config. It then dynamically loads the exact rooted pinned `tunnel.dll` and calls the upstream `WireGuardTunnelService(config)` exported implementation. The upstream signed `wireguard.dll` is loaded from the protected service installation directory, not from the caller's current working directory.
- Disconnect is session-owned only. It checks the same exact SCM ImagePath, requests stop, waits for removal, deletes the service, and removes only the exactly staged protected files if there are no foreign additions or directories. On failure it **does not blindly reset Windows Firewall or remove other WireGuard/WireSock services**.
- GUI report contains only categorical service state, DLL trust and `NOT_TESTED` evidence flags. It does not send local config, private key, endpoint, public IP, network topology or user info to GitHub or Oracle.

## Strong warnings (read before experimental use)

1. This is a **privileged, unsigned, early field Alpha** with incomplete unattended recovery. Do not install on an indispensable UU/remote-only Windows host. You MUST have a physically accessible Windows backup/test PC, local admin login and an out-of-band way to recover if it disables networking.
2. GitHub hosted Windows CI builds and packages all components and exercises nonmutating offline safety tests; it does **not** claim that this brand-new SCM lifecycle code successfully connected to a live server or survived reboot. Real integration will be separately tested before suggesting user use.
3. No custom WFP kill switch is installed. Direct IPv4/IPv6/DNS/UDP leaks can occur. Split /1 routing is not a leak guarantee and can still reroute most IPv4 traffic.
4. R83 `UnavailableProductionKernel` remains unchanged in the actual product manager. GA Issue #34 stays OPEN. R112 is a distinct explicitly named experimental executable/SCM namespace.
5. The ZIP is a GitHub Actions temporary *unsigned developer experiment*, not an authenticated publisher-signed public update. Windows SmartScreen, anti-malware, administrative policy and built-in driver signature enforcement must remain enabled. If Windows blocks execution, stop.

## Upstream supply-chain and licenses

- Official [WireGuard Windows embedding guide](https://www.wireguard.com/embedding/) and [embeddable DLL service README](https://github.com/WireGuard/wireguard-windows/blob/master/embeddable-dll-service/README.md): project embeds upstream `WireGuardTunnelService` via source-built `tunnel.dll`. Source compiled at pinned WireGuard Windows revision `6ece77bc487c8aa697e3c092197621c4f3e5ccb8`. Upstream embeddable source is MIT-licensed; retain copyright and license notices from the actual checked-out upstream source.
- Official [WireGuardNT binary distribution](https://download.wireguard.com/wireguard-nt/): CI verifies SDK 1.1 ZIP and AMD64 `wireguard.dll` exact SHA256 and Windows-valid Authenticode signature, plus a compiler-embedded DLL hash and same-dll verification at privileged native runtime. The WireGuardNT **source** is GPLv2, while official redistributed SDK binaries have their own more permissive distributed terms; release must include and honor the actual SDK's license text. No copied or rebuilt unsigned driver.
- The build includes `UPSTREAM_NOTICES.md` describing component provenance. No source code, trademark, licence or vendor identity implies that the Oracle Proxy application is an official WireGuard LLC product.
- This does not imply permission to reuse WireSock's SDK/decompiled driver; WireSock is independent and separately licensed.

## Lab acceptance still required

Before using a real Oracle production peer, test the R112 package on an externally recoverable Windows machine with synthetic disposable keys, an actual signed driver load, two-host UDP WireGuard handshake, loopback/network payload, correct service stop, exact-owned rollback, and true native Windows route/DNS state. After that, integrate optional source-only WFP diagnostics; full fail-closed WFP, UU control continuity, crash/reboot recovery, proper signed installer and secure updater are separate release gates. Nothing in this Alpha should replace working WireSock by default.
