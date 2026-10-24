# rc16 native receive allocation and official bandwidth policy

## Oracle policy checked 2026-10-24

The owner's last read-only metadata snapshot identifies VM.Standard.A1.Flex, two OCPUs, 12 GiB, uk-london-1, networkingBandwidthInGbps=2.0. Oracle's Compute Shapes table specifies 1 Gbps per A1 OCPU, maximum 40 Gbps for the shape family, and explicitly bases VM bandwidth on traffic within a VCN. The two-OCPU instance's 2 Gbps allocation is therefore not a guaranteed internet VPN rate or a promise of simultaneous 2 Gbps uploads and downloads to China. No interpretation of duplex aggregation is asserted without documentation.

- https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm
- https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- https://www.oracle.com/uk/cloud/price-list/

The 50 Mbps internet cap belongs to E2.1.Micro, not A1. The price list separately includes the first 10 TB/month of outbound traffic from Europe/UK; that is a traffic allowance, not a speed guarantee. No instance resize, paid resource or region migration is performed.

## Field evidence

rc15 native UDP8443 to BT PLC / Guildford: 233.00/2.85 Mbps (19826227013), 231.30/3.15 Mbps (19826230588). QUIC to the same target: 1.51/2.32 Mbps (19826233368). Returning to native UDP: 151.17/1.98 Mbps (19826238078). The changing native result prevents attributing all variation to transport. Owner separately confirmed UDP remained connected while speedtestworld measured 158.3/39.5 Mbps, then 194.6/37.7 Mbps, around 297 ms latency. This contradicts a universal 3 Mbps tunnel ceiling; browser speedtests alone do not independently establish the exit for every subrequest.

## Change and limits

Native UDP previously allocated a 4096-byte frame for every receive. A fixed per-connection pool now owns exactly 16 queued frames plus one per socket reader (68 KiB for fixed8443, 72 KiB for dual-port). Readers transfer ownership to the queue; consumers return storage only after copying or rejecting a frame. Queue depth, WireGuard bytes, crypto/session handling, physical binding, socket buffers, timeouts, protocol preference, native MTU1200 and TUN MTU1280 are unchanged. Storage never crosses to a new connection.

A deterministic producer with distinct 1232-byte frames measured 4351–4352 B/op and six allocations before; 256 B/op and five allocations after. Three repetitions on the same Linux executor: 2425–2806 ns/op before, 1420–1452 ns/op after. This isolates receive-path overhead; it does not measure Windows WAN throughput or promise lower geographic RTT. Queued-frame integrity, short reads, close, blocked primary, late/obsolete responses, rebind and socket policy pass Go race checks.

The server's opt-in read-only preflight additionally samples UDP counters and sanitized qdisc counters. No global TCP congestion, sysctl, MTU, firewall, quota or UU permissions are changed. Server kernel TCP congestion controls do not tune TCP sessions terminated by the Windows userspace WireGuard stack.

## Follow-up server queue evidence

Read-only production run40076050698/job120819496866 refreshed the same2Gbps metadata. Physical enp0s6 used pfifo_fast with26012 historical queue drops and no new drops during the approximately1.9s control snapshot; UDP RcvbufErrors276 was also historical and unchanged. Physical NIC error/drop counters remained zero; CPU load averages were0,0,0. This does not prove a bottleneck during the owner's speedtest. It supports evaluating FQ-CoDel for fairness and active queue management instead of increasing every global buffer. Opt-in queue application/rollback is separately documented in ops/oracle-project/README.md, with real namespace CI before production. No speed claim is inferred from historical counters.
