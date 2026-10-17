# R69 — Native WireGuardNT narrow-route pre-activation audit (disposable CI only)

R68 provided independently attended **official-client** public WireGuard IPv4 narrow-tunnel ICMP evidence, **not** a real remote tunnel using the repository's own Windows native engine. Before repeating on a real physical Windows system, R69 adds a **separate, restrictive, read-only CI pre-activation gate** to the existing true Windows WireGuardNT service-host + OS-authenticated manager GUI lab.

## Executable guard

The R69 stage executes on a disposable GitHub-hosted Windows runner **after** two independently ephemeral peer keys are generated and their two genuine WireGuardNT config files have been staged, but **before** any SCM tunnel services are registered or started.

It reads only two fixed protected lab config paths. It requires:

- exactly one Interface section and one Peer section per profile, strict field allowlist, duplicate/unknown key refusal, no scripts, DNS, Windows routing hooks, widened routes, comments, Unicode or injected sections;
- exact reciprocal /32 IPv4 and /128 IPv6 address/AllowedIPs pairs for the existing localhost-only G14 lab, fixed separate UDP listener ports and loopback endpoints;
- exact syntax and length for X25519 key material, with cryptographic verification that both peer-public keys correspond to the *other* ephemeral private key; all key material stays on the disposable runner and is never printed or published;
- negative tests for route widening, default IPv4/IPv6 routes, DNS, extra peers, endpoint change, ID spoofing, duplicated fields and CI invocation outside the exact hosted runner;
- an exact output marker only after success: R69_NARROW_ROUTES_NO_DEFAULT_DNS_HOOKS_PASS and R69_NATIVE_SCOPE_STAGED_BEFORE_SCM_PASS.

After the guard, the existing G14 live lab still requires official signed native components, GUI -> Windows-admin authenticated IPC -> LocalSystem SCM tunnel start, duplex Windows Winsock UDP and synthetic A/AAAA DNS traffic over the tunnel, actual peer counters, owned firewall cleanup, owned route/service removal, and physical OS route/DNS/firewall baseline restoration. Failures before startup still reach always-run cleanup steps.

## Boundaries

This guard audits **CI-generated lab configs only**. It is *not* a production profile parser, peer-provisioning mechanism, endpoint authorization or WFP guard. The actual default manager continues to construct UnavailableProductionKernel and rejects connection and disconnect. This test runs both synthetic localhost peers on **one Windows GitHub VM**. Neither official-client R68 nor CI-only R69 proves the native engine reached a real public Oracle endpoint, external IPv6 anti-leak, all-process WFP coverage, remote UU continuity or safe Windows installation.

Never copy actual public peer keys, any private key, Oracle addresses, usernames or credentials into public CI logs/docs. GA blocker [#34](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues/34) remains open.
