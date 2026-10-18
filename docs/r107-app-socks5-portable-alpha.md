# Oracle Proxy R107 — Windows x64 application-only SSH SOCKS5 portable Alpha (unsigned)

**This is an opt-in functioning application-layer SOCKS5 proxy candidate, NOT a WireGuard VPN and NOT a WireSock replacement.** It does not install a driver, system service, network adapter, firewall/WFP rule, routing, DNS or Windows system proxy. No system-wide anti-leak behavior is claimed.

## Build and distribution limits
- ZIP includes exactly two self-contained .NET 8 Windows x64 executables built from this repository's existing R55/R56–R59 sources, this README, the upstream engine licensing note, and SHA256SUMS.txt.
- GitHub Windows CI checks offline input refusals, job-owned child process cleanup, GUI creation, synthetic SOCKS/TLS tests, ZIP integrity and package allowlist. **A successful CI does not prove real Oracle SSH, two-host Internet traffic or UU compatibility.**
- Executables are **UNSIGNED**. Publisher identity and integrity are not established merely by a SHA manifest alongside the same ZIP. Do not disable SmartScreen, AV, application control or execution policy when Windows denies launch.
- Do not test on a critical UU-dependent remotely operated PC. No SSH private key, server identity or credential is bundled; nothing is committed to public CI logs.
- A GitHub Actions artifact is time-limited, not a signed public software release or update system.

## Optional testing on a separately recoverable Windows computer
1. Inspect repository source, CI provenance, the file allowlist and SHA256SUMS; extract the ZIP to a user-owned directory. No administrator rights or installation are needed.
2. Have the official Windows OpenSSH Client available and a server you are authorized to access through SSH. Keep host/user/private key data local.
3. Independently verify the server SSH host key fingerprint; register it in the user's %USERPROFILE%\\.ssh\\known_hosts. Missing trusted host-key data is a hard refusal; the client never asks you to disable host-key validation.
4. Select the existing local SSH private key from the GUI. Start OracleProxy.AppSocks5.GUI.Experimental.exe, enter server name/IP, SSH username/port, then explicitly click 连接应用级代理.
5. After it reports local 127.0.0.1:10880 readiness, manually configure **only a separate test application** for SOCKS5 at that address with proxy-side hostname resolution. R107 does not modify Edge, Windows, DNS or system proxy. GUI buttons can separately probe HTTPS destinations through the local SOCKS5.
6. Click 断开代理 or close the GUI. It stops only the owned helper/SSH process tree using Windows Job Objects. Other software remains untouched.

## Boundaries you must not conflate
- This proxy carries only traffic from applications explicitly configured to use it, principally TCP. Default Windows traffic, DNS, UDP, IPv6 and remote control can continue directly. It cannot satisfy a system-wide VPN/WFP leak test.
- It is not a replacement for WireSock's per-app packet handling, full-device tunnelling or a kill switch. No real WireGuard, Windows WFP, production Oracle wg0, routes, firewall, public peer or UU connection is touched by its CI.
- R83 ProductionVpnCoordinator refusal, UnavailableProductionKernel and GA Issue #34 remain operative.
- An eventual system-level VPN requires the upstream WireGuard embeddable DLL service, authenticated privileged service IPC, independent live WFP enforcement, safe On/Off, crash/reboot rollback, signed installer and real UU/IPv4/IPv6/DNS testing.

## Uninstall
First close the GUI and confirm its owned proxy helper exited; then delete only the extracted R107 directory. No R107 service, driver, route or WFP rule exists to remove.
