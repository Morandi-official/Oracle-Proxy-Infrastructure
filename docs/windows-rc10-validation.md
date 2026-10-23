# Windows rc10: native UDP reply-loss follow-up

## Physical evidence before the fix

MetaWise, rc9 `67e7b83b79866c55aef936033ca5917145c463ab`, China Mobile phone hotspot. Owner clicked UDP at 2026-10-23 13:07:20 Asia/Shanghai. Passive physical-interface counts from Oracle operation run [39899093551](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39899093551), attempt 2, job 120251281076:

| Port | Incoming WG-shaped initiations | Outgoing WG-shaped responses |
| --- | ---: | ---: |
| 51820 | 2 | 2 |
| 443 | 2 | 0 |

All four initiations and two responses occurred in the ten-second window ending 13:07:24. UDP8443 had 585 inbound and 419 outbound packets in the following ten-second window. Capture status OBSERVED; kernel socket drops 0. Only truncated headers and a four-byte type reached userspace; logs contain aggregate counts, no addresses, handshake keys or application payload. Counts alone are not authentication proof and are not per-device attribution; the owner-confirmed timing provides correlation.

Client diagnostics: native selected port empty, UDP attempt8198ms, HTTP/3 CARRIER_H3_READY but exit probe timed out after8180ms, final HTTPS. This establishes that requests reach Oracle, but does not distinguish return-path loss from local receive filtering. It does not establish carrier-wide WireGuard blocking.

## Implementation

Do not duplicate one initiation to two aliases of the same WireGuard peer: replay rejection can suppress the secondary after the primary has accepted it. Rotate aliases only for a distinct initiation from WireGuard's own retry timer. Ignore replies from an obsolete alias after a fresh attempt switches ports. Keep native packets unmodified; no obfuscation or HTTP/3 relabelling. The WireGuard retry timer is unchanged, so the first asymmetric-loss connection can require roughly five seconds before a backup initiation.

Remember an exit-verified native port for five minutes, bound to the physical network and protected in the SYSTEM DPAPI state. A new core can prefer that port; the cache never replaces fresh exit verification. Switching network or expiring the hint restores ordinary discovery.

An exit request starts with the existing short deadline. A WireGuard response received by the current core can extend that same request to a total of12seconds; outer HTTP/3 authentication alone cannot. Exit success still requires the fixed Oracle IP in the bounded HTTPS trace response. Diagnostic client_handshake_reply distinguishes current-client progress from an old server-reported handshake timestamp. Stale child-process callbacks cannot update the new core's progress.

## Local validation

- Shared-peer replay test fails against exact rc9 native source when only the primary response is lost. The same test passes on rc10.
- Primary success, primary request loss, primary reply loss, late obsolete response and synchronous primary send denial cases pass over real loopback UDP sockets.
- Real asynchronous delayed response: retain a4.2second probe after WireGuard progress; time out a silent carrier; reject the wrong exit IP.
- Windows .NET source compiles with zero warnings/errors; packaging allowlist tests pass.

## Remaining validation

Actual hosted Windows / Oracle acceptance has now passed as recorded below. MetaWise native UDP and HTTP/3 need physical retesting. This is an unsigned candidate, not GA: IPv6 is currently blocked; real logged-in UU crash/reboot continuity and publisher signing remain open.

## First main run: rejected for warm latency

[Run39906676193](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39906676193), source481fb25433792afe59ea399e37a1bfb4b3c55ba4, passed actual Oracle UDP cold runs3513/6238/6167ms (last two injected request/response loss), native443 under return-only loss, cached reconnect388ms and fresh-core cached-port recovery1248ms. HTTP/3 cold runs1952/3308/3195ms also passed.

It correctly failed REAL_WARM_CLICK_TO_GUARDED_PROXY_UNDER_ONE_SECOND at1483ms: UU19ms, persisted-state27ms, guard239ms, TUN active1391ms, complete1400ms. No accepted package was produced or released. PR190 precreates a new process-owned, sessionless dormant adapter before READY and keeps the subsecond assertion unchanged. Preflight must positively verify dormant status, no unicast addresses or forwarding routes, no TUN permission and an ordinary direct exit. The new core must refuse adoption of an existing adapter.

## Accepted main run

[Run39910454301](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39910454301), source `413e1ebc61a08469628cabb63b1cca0227e68403`, complete success. The ordinary owner observes dormant interface/IP state and service TUN-permission status through authenticated IPC; the separate SYSTEM fixture audits kernel routing. No SYSTEM DLL access is granted to the owner.

| Scenario | Measured milliseconds |
| --- | --- |
| Native UDP cold, ordinary path | 3554 |
| Native UDP cold, primary requests dropped | 6358 |
| Native UDP cold, only primary replies dropped | 6542 |
| Cached UDP443 reconnect with reply loss still active | 387 |
| Fresh core using exit-verified UDP443 port memory | 1269 |
| HTTP/3 cold runs | 1782 / 3001 / 3447 |
| Prepared native UDP click through authenticated IPC | 334 |
| Prepared HTTP/3 reconnects with native UDP blocked | 338 / 398 / 369 |

The unchanged subsecond prepared-click assertion passed. Activation breakdown: UU23ms, state30ms, guard212ms, TUN active284ms, service complete293ms. Measured IPC round trip334ms.

The main suite also passed fresh exit IP and DNS for each carrier, admin access inside the VPN, ordinary physical bypass blocking, actual TUN traffic counters, hard HTTP/3 core recovery without HTTPS, stale-generation verification rejection, HTTPS fallback, SYSTEM service crash recovery with the same device, usage linkage, explicit disconnect and logout. Candidate and corresponding-source artifacts were produced only after the complete suite passed.

These are cloud measurements. First cold native reply loss still requires a fresh WireGuard retry; there is no universal one-second cold-connect promise. MetaWise China Mobile hotspot retesting remains necessary. IPv6 forwarding, real logged-in UU crash/reboot continuity and publisher signing remain GA gates.
