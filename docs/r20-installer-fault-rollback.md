# R20: actual Windows SCM installer fault injection and reversible rollback

This extends the existing **STATUS-ONLY LocalSystem manager** installation
smoke test on a disposable hosted Windows runner. It does not install an
actual WireGuard VPN, WFP kill switch, driver or production secrets.

The CI installer now supports deliberately failing after (a) staging and
pinning its protected manager EXE, (b) registering an actual manual-start
LocalSystem SCM service and (c) starting the genuine service. At each
checkpoint a separately run test confirms the expected failure was raised,
the original installer finally-cleanup deleted only its own service/folder,
and default IPv4/IPv6 routes, DNS and Windows Firewall rule count exactly
match the pre-test baseline. A preexisting staging directory with a sentinel
file is refused and preserved. After all injected failures, a normal clean
install, GUI authenticated status request and full uninstall must still pass.

These checks are intentionally limited to **process-level simulated
exceptions**, not actual power loss during NTFS/SCM writes or rebooted
recovery; crash consistency and abandoned install receipts are still open.
Future production requirements include a signed installer and updater,
verified managed Native WireGuard bundle and DPAPI key handling, SYSTEM-
owned whole-device WFP fail-close, explicit OFF rollback and independently
tested emergency recovery.

No production system, WireSock, Oracle instance or UU remote control is
touched. Issue #34 remains open.
