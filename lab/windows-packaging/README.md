# R5: reversible STATUS-ONLY installation on disposable cloud Windows

This is a **packaging lifecycle smoke test**, NOT an installable VPN.

On disposable GitHub-hosted Windows only, CI compiles a production-restricted
read-only GUI and read-only LocalSystem manager. It protects a fresh temporary
staging directory with SYSTEM/Administrators ACL, pins the exe hash in an
ownership manifest, creates a fixed manual-start SCM service, verifies real
GUI-to-manager authenticated status IPC, then removes the exact service
and deletes only its own staged files.

Before/after checks compare default IPv4/IPv6 routes, DNS server configuration
and Firewall rule count. These are smoke checks, not proof of no leakage.

The test refuses non-CI environments, pre-existing service names or folders.
It must NEVER be run on the UU-dependent computer. It contains no WireGuardNT,
tunnel.dll, WFP filters, VPN configs or arbitrary start/stop commands.
No installer, manager or experimental VPN control binary is uploaded for users.

The real functional Alpha still requires a trusted native engine bundle,
production OS-authorized GUI-to-SYSTEM connect/disconnect, durable intent,
actual WFP IPv4/IPv6/DNS fail-close and independent recovery, followed by
external network and UU acceptance. GA additionally requires production
signing, licensing, complete rollback and independent evidence.
