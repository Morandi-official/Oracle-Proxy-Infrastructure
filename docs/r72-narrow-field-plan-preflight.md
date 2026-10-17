# R72 — Public peer proposal scope admission (OFFLINE REVIEW ONLY)

## Why

R68 proved a real public tunnel with the official Windows WireGuard client. R69 and R70 proved genuine native Windows WireGuardNT can exchange test data only **between two lab peers on one disposable Windows runner**. R71 proved the independent no-VPN read-only diagnostics executable worked on an actual physical Windows x64 machine, with no privilege elevation. None of those results authorize connecting the project's own engine to a real Oracle endpoint.

Before building an attended native field test with new public server identity, R72 adds an independent offline metadata **proposal reviewer**, not a client, tunnel service, installer, key store or consent mechanism.

## Operator-reported R71 physical Windows evidence

2026-10-17: operator supplied a Windows PowerShell transcript from the physically accessible second test computer. Downloaded EXE SHA-256 exactly matched the prior successful GitHub run: `0AD42ADC2B0A6701045B5697D082EC94908C0C89922900C31B81CB392E846B2C`. `--self-test` printed `R71_READONLY_CLI_NO_MUTATING_COMMAND_PASS` and exited 0; `--review-only` produced schema v1 and exited 0. It reported Windows x64, non-elevated token, session matching the active console, a completed enumeration of one up Ethernet/Wi-Fi candidate, BFE and Windows Firewall service status running; VPN/WFP/IPv6 leak/UU/signing and authorization flags remained **false**. No keys, network addresses or identities were included in the transcript.

The `network_mutation_performed=false` report is a source-code promise, **not** independent evidence of packet-level no-leak or absence of OS mutations; main CI separately compared real routes/DNS/adapters/firewall/service states on hosted Windows. An active-console session alone is not witnessed physical emergency recovery. The operator has **not yet separately confirmed** ordinary networking and UU after this specific R71 run; do not mark that check passed.

## R72 executable scope review

`lab/field-windows/r72_narrow_plan.py` validates a **fresh proposal's metadata only**. It never invokes Windows tools, WireGuard services, WFP or network requests, never generates or opens private keys, never writes configuration, and never returns a permit token. Any unlisted property (including SSH secrets, config hooks or approval tokens), repeated JSON key, invalid IP, broad route, IPv6 path, unknown DNS/firewall/driver policy, missing client/server public identities, reused R68 inside IP, or stale/extended expiry is rejected. It is deliberately constrained to a future isolated tunnel-only client `10.77.72.2/32` -> test server `10.77.72.1/32`, with **AllowedIPs exactly that single test-server /32** and UDP test port 51828. These are PRIVATE **inner** addresses, not a public Oracle endpoint; no real external IP or key is checked into the repo.

Metadata needs two distinct public key strings (never private), newly observed client public IPv4, server global unicast IPv4, 5–20-minute proposed time window, exact no-default-route/no-DNS-change/no-firewall-change/no-driver-install flags and an explicitly present statement that **separate operator approval is still required**. The two public IPs/keys are input to a future operator-authored local JSON and **must not** be posted publicly or automatically uploaded to CI. A validated metadata digest can be reviewed as a scope fingerprint; it is **not** a cryptographic signature, connection license, measured OS state or proof that an endpoint is reachable.

Cross-OS hosted CI must exercise negative adversarial mutations and forbidden command invocation using synthetic unowned addresses and fixture-only non-secret public key bytes. The workflow produces **no installer or distributable VPN**.

## Requirements before changing real hosts

1. Independently design and review the actual native Windows SCM test runner, strict trusted binary provenance, temporary owned staging, independent 15-minute watchdog and exact rollback under observed adapter/interface churn. The current release `UnavailableProductionKernel` must remain unchanged.
2. Obtain separate affirmative permission for any Windows native service/driver installation and any Oracle ephemeral interface, NSG attachment or firewall mutation. The R71 read-only permission is not enough.
3. Use new per-run generated keys, fresh observed client source IPv4 and newly created test server identity. Never reuse R68 private keys or assume the former Windows public IP persists.
4. Keep on-device physical console recovery, SSH and independent server console available; validate UU and ordinary Internet before, during and after. Fail closed, do not modify production wg0, WireSock, UU, default routes, Windows firewall or system DNS.
5. Only if the **project's own** native client can make authenticated cross-host traffic and disconnect safely should this gate progress. External IPv6/DNS all-app WFP and production readiness remain separate unsatisfied gates. Issue #34 remains OPEN.

## Source boundaries

This report uses the operator-provided PowerShell text for R71 physical evidence. CI and R68 references are tracked in docs/r68-public-path-official-wireguard-manual-evidence.md, docs/r69-native-route-profile-preactivation-audit.md, docs/r70-native-active-route-dns-ci.md and docs/r71-attended-field-readiness.md.
