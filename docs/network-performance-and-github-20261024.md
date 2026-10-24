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
