# Windows rc11: explicit protocol retry, safe exit and native receive evidence

## Owner rc10 results

MetaWise Windows, China Mobile hotspot, rc10 `413e1ebc61a08469628cabb63b1cca0227e68403`. At2026-10-23 15:47 Asia/Shanghai, reconnect took743ms but reused H3 core PID46388 and the native attempt timestamp1792739947. That reconnect did not retry native UDP. Rechoosing the same combo item did not trigger SelectedIndexChanged.

Disconnecting, selecting H3, then selecting UDP forced a new attempt. Owner clicked15:51:00; native start1792741858; UDP elapsed8008ms, stage CARRIER_NATIVE_TRY_443, selected port empty. Final H3 core49732; click-to-ready7636ms because native preparation began before the click. Current-core client_handshake_reply=true belongs to H3, not the failed native core.

Oracle passive header-only observation: run39918511454 attempt3, job120303140043, source b177dfafabf85d6aa2034d01059871b650ddbf96. Duration300seconds, started1792741658, finished1792741958, socket drops0.

| Physical port | Incoming WG-shaped initiations | Outgoing WG-shaped responses | Window ending UTC epoch |
| --- | ---: | ---: | --- |
| 51820 | 1 | 1 | 1792741860 |
| 443 | 1 | 1 | 1792741870 |

The fresh secondary initiation now elicits a server response, unlike rc9's duplicate replay. Both response paths still fail to produce a client-native selection. These aggregate counts are correlated by owner timing, not per-device attribution or authentication proof. They do not distinguish return-path loss from local receive filtering, and do not prove carrier-wide blocking. No further Oracle ingress change is justified by this observation.

Earlier attempt1 (job120297765055) was missed by the owner. Attempt2 (job120300574714) only saw H3 traffic; the owner-confirmed15:47 reconnect was after its window and reused an old H3 core. Neither is evidence that a fresh native request failed to reach Oracle.

## Changes

A new connection with explicit UDP/HTTP3 preference retries that primary instead of reusing a different warmed fallback. Auto retains fast learned fallback reconnect. User selection commits restart discovery even if the selected value is unchanged.

Normal window close and the explicit disconnect-and-exit action use one fixed, authenticated service command. Stop the core, verify owned tunnel removal, persist disconnected intent, then clear owned protection. The account remains; the system service stays available without a core or preparation lease. Standalone Disconnect retains warm preparation. Unexpected GUI loss and OS shutdown preserve fail-close intent.

Native per-port evidence records bounded numeric initiation/response/cookie/invalid/obsolete and socket-error events. It never exports raw stderr, addresses, payloads or keys. Intended closure of a losing socket is not a read error. Failed native evidence is captured before fallback destroys that core. A response-shaped packet alone cannot authenticate a peer or authorize connected state.

## Validation

Local .NET compilation: zero warnings/errors. Real loopback primary, request loss, reply loss with shared replay state, obsolete reply, synchronous send failure: pass under Go race detector. Packaging and publisher boundary tests pass.

Final PR723b3e8712e7bbe2753155f3c791d50ac5522e29 checks all passed; merged as d7dbdb5ca0d3dda09cab62a7d21f6eb83cf34a7b. Main run39921449520, job120307403713, completed successfully with full real Oracle acceptance. Main must cover explicit primary retry from warm H3, safe quit from prepared/connected states, retained account, no idle core restart, ordinary direct restoration, plus existing security, crash, DNS and real Oracle protocol gates.

Physical native UDP is not resolved. IPv6 remains blocked; actual UU crash/reboot continuity and publisher signing remain GA gates.

Owner read-only disconnected adapter/route output: the only IPv4 default route is WLAN, MediaTek MT7922, index8, route metric0; no0/1 or128/1 route. WireSock adapter16 and OracleProxy57 are disconnected. No third-party security software reported, only Windows Security. Prior FlClash TUN use is not evidence of an active route conflict. No adapter deletion or firewall disabling requested.

## Accepted main evidence

Actual native UDP cold3812ms; injected primary request loss6902ms; primary reply-only loss6581ms, both remaining native viaUDP443. Cached443 reconnect371ms; fresh-core remembered443 reconnect1695ms. HTTP/3 cold2152/2452/2488ms. Prepared native click378ms; Auto HTTP/3 warm reconnect381/520/581ms. These are cloud results, not MetaWise measurements and not a universal subsecond cold guarantee.

REAL_EXPLICIT_UDP_RECONNECT_RETRIES_NATIVE_INSTEAD_OF_REUSING_WARM_QUIC passed. REAL_QUIT_STOPS_PREPARED_CORE_AND_RETAINS_ACCOUNT, REAL_QUIT_LEAVES_AUTHENTICATED_SERVICE_IDLE_WITHOUT_CORE_RESTART and REAL_QUIT_WHILE_CONNECTED_STOPS_CORE_AND_RESTORES_DIRECT all passed. Existing real HTTP/DNS/admin-through-VPN, physical bypass block, actual GUI/core/SCM crash, HTTPS fallback, same-device recovery and billing linkage gates passed. Full run ended REAL_ORACLE_CLIENT_END_TO_END=PASS.

Client/source artifact IDs12488062138/12487608669 are pinned by exact archive SHA256 in ops/distribution/windows-rc11.json. Public promotion still must verify archive content, matching metadata, inner client/source digests and exactly four release assets before publishing.
