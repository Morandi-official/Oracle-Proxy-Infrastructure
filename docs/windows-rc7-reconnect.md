# Windows rc7 reconnect acceptance

Owner rc6 evidence: MetaWise repeatedly needed 15–23 seconds, ending on QUIC;
`connect_switch_ms=1079` measured only the synchronous service command, not the
whole wait for a verified usable exit. Healthy UDP cloud timing did not cover it.

rc7 keeps a live, authenticated core in standby on explicit Off. It ends the
TUN session, removes its IP addresses, nonlocal routes and DNS settings, audits
the dormant adapter, saves Off, and clears the owned WFP rules.
Ordinary applications use direct networking; the private authenticated SOCKS
probe alone keeps the encrypted carrier ready. The standby expires 20 seconds
after the last GUI Prepare request, and Logout stops it immediately.

Connect reuses an in-progress preparation instead of restarting its UDP timeout.
It still freshly verifies UU identities and installs the persistent guard before
activating the TUN. The second complete WFP policy rebuild is replaced by a
SYSTEM-only live lease operation requiring an existing persistent/boot guard,
the actual OracleProxy interface, and an attested live SYSTEM core in session 0.
No new GUI commands, destinations or privileged configuration fields are added.

Failed carriers are remembered in memory for five minutes on the same physical
network. Interface/address/gateway changes clear this hint and restart at native
UDP; profile and account validity are still independently checked. Initial
preparation remains UDP, QUIC is the first backup, and HTTPS is the final backup.
A functioning live carrier is not interrupted just to expire a preference hint.

Diagnostics distinguish `connect_switch_ms` from `click_to_ready_ms`, which ends
only on verified exit availability (or activation of the same recently verified
standby). Both carry phase timing without credentials or network identifiers.
The GUI polls pending state more promptly and names the prepared carrier.

Acceptance must cover three repeated sub-second QUIC reconnects while native UDP
is continuously blocked, Off direct traffic with no active TUN or nonlocal routes, fresh HTTP and UDP DNS
after each Connect, remembered failure after core loss, network-hint reset,
missing-guard/wrong-process lease denial, and existing SCM fail-close recovery.
First-ever cold startup, unavailable carriers, long WAN round trips and a failed
network cannot have an unconditional one-second guarantee. Real MetaWise timing
and actual UU sessions still need owner confirmation after cloud acceptance.
This remains unsigned, IPv6 blocked, and not GA.

## First main acceptance evidence and follow-up

Run 39719965235 measured a 402 ms prepared native switch and passed native UDP recovery and QUIC exit/DNS/Off checks. Its first retained QUIC reconnect was 1646 ms, so the strict one-second gate failed and no candidate was published. The relay /32 exclusion expands into many prefixes; Windows route creation was serial. The follow-up build vendors the pinned dependency and applies an exact SHA256-preimage patch to create the same routes with at most four independent concurrent calls, waiting for every call before success or teardown. The full modified source ships in the corresponding-source archive. Reconnect phase measurements are printed for all three strict cycles. No change to prefixes, gateways, routing exceptions, fail-close policy, or the one-second acceptance threshold.

## Dormant adapter follow-up

Run 39721739898 reduced native warm switching to 377 ms, but QUIC reconnect was 1339 ms: UU discovery 25 ms, saved state 35 ms, guard installed 207 ms, TUN active 1315 ms, complete 1323 ms. Thus route concurrency alone was insufficient and the candidate was not published. The next pinned source modification retains only the OracleProxy adapter handle between sessions. Off ends the ring session, clears the adapter IP addresses, every owned route and DNS settings, and closes the dynamic strict-route filters. Cleanup errors close the adapter and retain protection rather than acknowledging Off. The SYSTEM controller checks dormant status, absence of usable unicast addresses and absence of nonlocal routes before clearing protection. Link-local/multicast OS routes are allowed only on the inactive adapter. Reactivation reuses the same adapter handle; EOF explicitly closes the cached handle. Kernel process-handle teardown also removes it on a crash. This changes the Off adapter lifecycle: a dormant adapter may remain visible, but it does not carry application traffic. The same strict real Oracle three-cycle gate remains.

## Ownership boundary

Dormant reuse is restricted to the same already-running private core. New core startup, service initialization, stopped-core disconnect and emergency recovery require complete adapter removal. The isolated fixture also verifies removal after EOF before replacing the process. This prevents adoption of an unrelated or still-removing same-name adapter.

## Pre-ownership-patch performance evidence

Run 39724272297 passed real Oracle end-to-end acceptance: native warm click 390 ms; with native UDP continuously blocked, three retained QUIC reconnects measured 313, 383 and 258 ms, each with fresh ordinary HTTP and UDP DNS. Remembered carrier failure after core loss, HTTPS last fallback, SCM fail-close recovery on the same device, quota usage linkage and explicit Off direct traffic passed. Final release must use a successful main build including the ownership boundary above; these earlier timings are not a MetaWise measurement or an unconditional cold-start claim.

## Verification ownership

Run 39740508895 passed native recovery and SCM fail-close recovery, then failed immediately at the next QUIC stage. Code review found that automatic dead-core replacement called StartCore without the runtime StopCore path, retaining the old successful exit timestamp. The fix resets verification at every start and binds every successful probe to the runtime generation; WarmReady requires the exact generation. A real Oracle regression blocks native UDP, kills the prepared core, waits for the background replacement and rejects readiness or a retained timestamp on that new unverified generation. Only then does it proceed to QUIC fallback and three strict reconnect cycles. Fixed cleanup/command phase fields distinguish deactivation, audit, durable state and guard-clear failures without exporting raw exception messages or credentials.

## Final accepted build

Source `e70ff24b41e3b81dcc20106501f58053d65cba0b`, main run 39744006755, build job 119707868028: PASS. Native prepared click 412 ms. The forced background replacement regression passed without inherited verification. With native UDP continuously blocked, the three prepared QUIC reconnects were 324, 328 and 316 ms; fresh ordinary HTTP and UDP DNS passed after every cycle. Same-device SCM fail-close recovery through HTTPS while both UDP carriers were blocked, usage linkage and explicit Off direct traffic passed. This does not establish one-second cold start or MetaWise timing. Actual logged-in UU and physical reboot acceptance remain pending; unsigned, IPv6 blocked, not GA. Client and complete modified corresponding source are pinned in `ops/distribution/windows-rc7.json`; publication is draft-first and verifies uploaded SHA256 digests before release.
