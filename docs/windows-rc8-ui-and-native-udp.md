# Windows rc8: preparation display and native UDP reachability

The owner reports that rc7 QUIC reconnects now take less than one second after an initial approximately twelve-second wait. Native UDP has not yet succeeded on MetaWise. This is separate from cloud native UDP acceptance and must not be marked resolved on the owner's machine without its own evidence.

## Display fix

Preparing snapshots were rendered every 250 ms. Each render first wrote the short generic detail, then the long preparation detail, then optionally the stale-usage warning. AutoSize labels moved every following row repeatedly; passive status reads also disabled and enabled the action buttons. rc8 computes the complete detail before assigning it, buffers flow panels and does not toggle action buttons for passive reads. A ready standby returns to three-second polling. The pending preparation and protected states retain fast updates. A click arriving during a read waits for that read rather than being discarded.

The Windows fixture subscribes to actual TextChanged, EnabledChanged and Layout events, repeats idle and preparing polls, and checks that a Connect request queued behind a pending status read is executed. It does not use account credentials or change networking for this regression.

## Native UDP evidence

The deployed primary is kernel WireGuard UDP 51820, backup is QUIC UDP 8443, final fallback is HTTPS/TLS TCP 443. Prior accepted cloud Windows run 39744006755 exercised native WireGuard through the real Oracle public exit with ordinary HTTP and fresh UDP DNS. That proves this server path for the runner, not reachability from the owner's phone network.

The rc8 diagnostic retains only fixed fields from the most recent native UDP attempt after QUIC fallback: endpoint_port, socket_binding, started_at, started_without_tun, probe_result, probe_failures and attempt_elapsed_ms. These describe an attempt and its HTTPS exit probe; a timeout does not prove whether a WireGuard handshake reached the server. No keys, token, account name, physical interface identifier, raw log or configuration is exported.

If Oracle console rules need correction, inspect the actual instance primary VNIC's subnet security lists and attached NSGs. The intended inbound native rule is stateful UDP, source CIDR 0.0.0.0/0, source port range all, destination port 51820. QUIC 8443 does not open native 51820; an NSG name containing 51828 is not evidence of its active rules. Avoid modifying SSH, existing 443/8443 rules, or opening unrelated port ranges. Confirm existing rule values before making changes. If rules are already correct, investigate client/carrier path rather than claiming that another identical ingress rule solves it.

After an ingress correction, upgrading/restarting the product service clears its in-memory failed-carrier hint; on the same running service that hint may last five minutes. Closing the GUI alone does not restart the service. A new native attempt must receive actual Oracle exit verification before the UI reports UDP connected.

This remains an unsigned acceptance candidate. IPv6 is blocked pending infrastructure; actual UU fault/reboot continuity remains unverified.

## Owner console rule evidence and connected native socket

The owner supplied both actual rule lists: the subnet security list has stateful UDP 51820 from 0.0.0.0/0, all source ports. The attached NSG has an old source-restricted UDP 51828 test rule and global UDP 8443. OCI security-list and NSG allow rules are combined; the absent NSG 51820 rule does not override the subnet allow. No duplicate rule or new console action is required by this evidence. UDP 443 is also allowed at the subnet, but that alone does not establish a WireGuard listener/forwarder on 443.

The native endpoint previously used the upstream wildcard dual-stack StdNetBind listener/egress-pool path. The successful relay carriers use a destination-specific physical dialer. rc8 selects a direct detour for the native endpoint, with a bounded five-second socket connect timeout; this causes upstream ClientBind to dial the actual IPv4 WireGuard peer using a connected UDP socket. Wire bytes remain native WireGuard, without TLS or QUIC. The ordinary application final route is still WireGuard; the direct helper is selected only by the endpoint, under the same SYSTEM/core WFP identity restrictions. The isolated Windows fixture binds this helper to its loopback peer. This addresses a binding-path difference, not a proven mobile-provider diagnosis; owner UDP reachability remains open until retested.

Read-only server preflight PR181 was merged at 9a77bbf9aea06ab054117d135cb7aceb8560110c. Operations run 39751212221 / job119731954286 succeeded: observed wg0 listen_port=51820, udp_listener_present=true, simple_any_source_accept_rules=1, conditional_accept_rules=0. These bounded guest observations plus the supplied OCI rules do not identify a remaining console configuration change. No server firewall or service settings were changed by this request. Backend application, lifecycle, management-browser and source-safety checks also passed.

## Accepted main candidate

PR180 merged at 0d725c7af203a0e89348e27f1a99b395d571534d after Windows PR run 39751107881 and source-safety passed. Main run 39752161820 / build job119735119798 passed real Oracle acceptance and entered package assembly. Final publication must wait for the entire run to succeed and pin its uploaded artifacts. MetaWise native UDP and corrected display still require owner confirmation; the prior owner already confirmed sub-second prepared QUIC reconnects.

Full main run 39752161820 succeeded. Native connected IPv4 UDP 51820 preparation was verified before TUN activation; guarded warm click 398 ms. With native UDP held blocked, QUIC reconnects measured 281/302/273 ms; retained native failure diagnostics, fresh ordinary HTTP/UDP DNS, HTTPS last fallback, SCM fail-close recovery on the same device and account usage linkage all passed. UI repeated-read/layout/button and queued-click regressions passed again. Client wrapper artifact12414642439 and complete source wrapper artifact12415130087 are pinned in windows-rc8.json; their outer archive digests are not the downloadable inner payload hashes.
