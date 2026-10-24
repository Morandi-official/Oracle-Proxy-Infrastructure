# Network performance and GitHub resource diagnosis (2026-10-24)

The owner confirmed rc14 native UDP8443 stability, then reported a Slough Speedtest result of48.66Mbps down,3.64Mbps up and244ms latency. This is one endpoint/path measurement, not an Oracle bandwidth entitlement or a per-client speed cap.

Read-only Oracle preflight run40065065968 / job120786459334 confirmed VM.Standard.A1.Flex in uk-london-1,2OCPUs,12GiB RAM and a2Gbps networkingBandwidthInGbps allocation. The host had ample memory and near-zero load; physical interface error/drop counters did not increase. Official compute shapes documentation specifies1Gbps per A1 OCPU. The Always Free50Mbps public-internet limit belongs to VM.Standard.E2.1.Micro, not this instance. Shape bandwidth is an upper bound, not a guaranteed rate to China Mobile.

Official references:
- https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm

Cloudflare upload/download controls returned HTTP errors, so no server-direct speed was established by those requests. Do not report a fabricated bandwidth measurement. GitHub page, avatars, raw content and the reported CSS all returned HTTP200 from Oracle.

The Windows controls found avatars.githubusercontent.com resolving to127.0.0.1 and curl receiving502 from remote_ip127.0.0.1. The owner then identified27 GitHub-related hosts entries and Steam++.Accelerator listening on443. This local HTTPS intermediary explains the502 resource failures and consequent CORS errors. After disabling Steam++ GitHub acceleration through its UI, DNS returned the normal185.199.108-111.133 addresses. No project code removes hosts entries or weakens TLS validation. A new read-only client diagnostic detects loopback DNS mappings and reports fixed public GitHub endpoint HTTP status/timing without credentials.

An initial32/128KiB TCP-buffer suspicion was disproved by tracing NewGVisorStackWithOptions: it internally passes isLocalStack=false. The actual desktop buffers are1MiB initial,8MiB receive maximum and6MiB send maximum. Retain these values. A compiled dependency regression checks the actual WireGuard stack policy, buffer sizes and MTU.

rc15 changes the actual userspace WireGuard TCP endpoint from Reno to CUBIC with an exact-preimage source patch. Changing the Oracle kernel TCP congestion setting would not tune forwarded client-owned TCP sessions. IPv4-only DNS matches the current IPv6-block policy; future tunnel policy retains dual-stack preference. Stable TUN1280 / inner WG1200 MTUs, transport selection, WFP and UU policies remain.

Controlled same-version gVisor model, FIFO100ms delay in each direction,6-second received-byte sample after2-second warm-up:

| Deliberate loss schedule | Reno Mbps | CUBIC Mbps |
| --- | ---: | ---: |
| None |81.019|79.898|
| Eligible data at every120th packet position |0.654|0.776|
| Eligible data at every600th packet position |3.006|4.871|

Reproduce in clients/windows/product/ci/tcp-latency with `go test -v -timeout 70s`. This controlled model isolates congestion policy; it is not the complete Windows/Oracle/hotspot path and does not promise these rates or multipliers in production. Use the full Windows real-Oracle acceptance before packaging. Preserve exact modified dependency source in the corresponding-source archive.

The owner's later297.05/3.58Mbps result used another test server and still displayed the old Oracle exit; after refresh it displayed a China Mobile exit but the test did not finish. Neither is a clean matched-server direct baseline. Keep this limitation when interpreting client improvements and the hotspot upload ceiling. Geographic/route RTT cannot be eliminated by client tuning.

A second concrete transport difference was found in the native connected UDP bind: it bypassed wireguard-go/conn/controlfns_windows.go, where the standard bind requests7MiB receive AND send buffers. Restore that per-socket policy through the owned socket's RawConn; never force global system limits. Record bounded numeric before/after sizes and option errors, permitting OS clamps. A real loopback test validates wrapper unwrapping and observes actual values; a negative test ensures a successful RawConn.Control does not erase a setsockopt error. The Windows actual-Oracle gate requires the7MiB policy to have applied on the real carrier socket. This does not claim the owner's original socket values or a measured hotspot speedup before rc15 field feedback.

The first rc15 main run40066826963 stopped at104seconds of healthy nativeUDP because the fixture bounded total ACCOUNT usage to16MiB per run. Concurrent field traffic on another device can invalidate that account-wide delta. The fixture now retains the same16MiB bound using only this device's peer RX+TX counters, refuses missing/regressing counters, and separately retains real account-budget and usage-linkage checks. A nonshipped regression verifies other-device usage cannot trip or bypass the per-device bound.

Additional field data: a local speedtest.cn direct test reached278.06Mbps down/51.82Mbps up/35ms; a separate international rc14 UDP result19826023692 reached192.79Mbps down/3.61Mbps up/235ms to Virgin MediaO2 Slough. Different targets prevent a strict tunnel-overhead calculation, but the hotspot has demonstrated substantially more than3.6Mbps upload capacity. The earlier fixed50Mbps speculation is unsupported for this A1 instance.
