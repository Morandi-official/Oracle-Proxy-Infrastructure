# R111 — Oracle Proxy WireGuard Functional Alpha (Windows x64, unsigned, explicitly UNSAFE as a WireSock replacement)

This is a genuine **opt-in tunnel service control candidate**, not only a SOCKS5 proxy or simulation. It invokes an *independently installed official WireGuard for Windows* binary via the documented `/installtunnelservice CONFIG_PATH` and `/uninstalltunnelservice TUNNEL_NAME` entry points. It attempts to create a service named **exactly** `WireGuardTunnel$OracleProxyAlphaTest` using a user-supplied, separately authorized test config named **exactly** `OracleProxyAlphaTest.conf`. The service handles encrypted traffic if upstream prerequisites and peer reachability are valid; whether this R111 GUI actually passes real two-host traffic **has not yet been tested**. Do not mistake a running SCM service for a proven VPN handshake.

## What is and is not shipped

- The ZIP includes an **unsigned** standalone C#/.NET 8 Windows Forms GUI, this README and SHA-256 manifest. This is **source-built CI artifact, NOT an Authenticode-signed installer**. No private key, peer config, upstream installer, external server endpoint, driver or user configuration is bundled.
- R111 refuses to launch on non-Windows, requires a native elevated Administrator session before any tunnel mutation, and never automatically asks for elevation or disables SmartScreen/antivirus/Windows script execution controls. It refuses to start if the fixed service name already exists or is unknown; it cannot hijack an unrelated WireGuard service. It only offers a Stop action for a service attempted **during the same GUI process session**.
- Before launching it verifies the installed `%ProgramFiles%\WireGuard\wireguard.exe` has a Windows-valid Authenticode signature and an expected WireGuard LLC signing certificate subject. This check uses offline/cached chain validation (not independent proof of revocation status). The Windows command arguments are built without a shell; no private key or full config is printed in logs.
- The GUI checks a bounded plain-text config, rejects reparse file links, arbitrary name, `PreUp/PostUp/PreDown/PostDown` script directives, routing overrides, unsafe unpaired IPv4 /1, and any `AllowedIPs` /0 route. It does not secretly edit the user's config, routes, system DNS, host WFP or WireSock.
- R111 contains **no custom WFP kill switch** or post-crash automatic recovery. The existing R83 `UnavailableProductionKernel` remains blocked in the separate default product/manager build, and GA #34 remains OPEN. R111 is a separately named experiment outside that production service.

## Important official WireGuard behavior

Official WireGuard for Windows itself automatically configures routes and may set Windows firewall rules according to `AllowedIPs`. With a one-peer `0.0.0.0/0` or `::/0` configuration it can enable an aggressive automatic kill-switch. Since R111 has no verified recovery, it **refuses any /0 AllowedIPs**. For a *full-route-like IPv4 experiment without that /0-specific automatic kill-switch*, an explicitly paired `0.0.0.0/1, 128.0.0.0/1` route is accepted (IPv6 must be considered separately). This still changes system networking and **DOES NOT prevent IP/DNS/UDP leaks** and cannot promise remote-control preservation. Source: [WireGuard upstream Windows routing/firewall description](https://github.com/WireGuard/wireguard-windows/blob/master/docs/netquirk.md). This is not permission to test on a critical UU-controlled computer.

## Manual testing — ONLY on a separate, physically attended, recoverable Windows PC

1. Do **not** install R111 onto either critical UU-hosted computer or an irreplaceable remote-only server. Have a known-good administrator login and physical keyboard/screen, and a separate way to recover network connectivity if the tunnel changes default routes or DNS.
2. Install the **official** WireGuard Windows application from [wireguard.com/install](https://www.wireguard.com/install/), keeping Windows security settings unchanged. Do not install untrusted alternative DLL/SDK binaries.
3. Securely create an independently authorized, real WireGuard peer config named `OracleProxyAlphaTest.conf` (never commit/upload it to GitHub). Choose a separate test identity and a peer that the operator is authorized to reach. R111 cannot generate a production credential or reconfigure Oracle. It requires an exact file name, a single peer and no /0 AllowedIPs or arbitrary hook scripts; the config may use a paired IPv4 /1 route after the operator reviews its implications.
4. Unzip R111 in a user-owned folder. Check SHA256SUMS.txt and inspect GitHub source/CI; the ZIP is **unsigned**. Do not disable Windows SmartScreen or AV to open it. If blocked, stop.
5. At the local physical keyboard, explicitly start `OracleProxy.WgAlpha.exe` **as Administrator**. Click **选择配置并连接（实验）**, select the config, and confirm the warning. The GUI uses the fixed official `wireguard.exe /installtunnelservice` route. A running Windows service is **NOT** two-host handshake proof.
6. From a **different** independent device/site, verify handshake and traffic, external exit IP, normal TCP/UDP/DNS behavior and any direct leaks; note failures and disconnect immediately if remote-control access changes. The existing R108 precheck and new R111 local JSON report are supplementary only. **Never send private keys, config contents, real network topology or personal IPs to a GitHub issue**.
7. Click **断开本次创建的隧道** while the GUI remains open. Confirm the dedicated service disappears, then manually confirm that default routes, DNS and direct Internet access recover. The GUI explicitly does **not** claim this is automatic safe-Off, nor will it uninstall a service created by a different process.

## Manual recovery if Alpha crashes or fails to disconnect

Because R111 is intentionally published before safe recovery testing, **the operator must retain local administrative access**. At a local administrator console, inspect `WireGuardTunnel$OracleProxyAlphaTest` in Windows Services. If it is precisely the service you created for this experiment, use the official signed WireGuard executable:
```powershell
& "$env:ProgramFiles\WireGuard\wireguard.exe" /uninstalltunnelservice OracleProxyAlphaTest
```
Do not remove anyone else's WireGuard service, reset Windows Firewall globally, disable Windows Defender, delete any UU/WireSock driver, or bypass execution policies. If the system cannot be restored from a local keyboard, you should **not have run this test on that computer**.

## Test claim boundaries

CI tests `--offline-self-test` (configuration refusal, service-name guard, no arbitrary privileged CLI, publish payload file allowlist, unsigned status, archived hash consistency) on GitHub hosted Windows. **CI does not open a real WireGuard tunnel or alter its firewall/route.** When you test, the user must confirm independently whether their server/keys and WireGuard service actually connect; a failed config cannot prove any Oracle bug. R111 is a separately controlled early field experiment and not an approved WireSock swap, release candidate, signed installer, automated rollback or full-device fail-close VPN.
