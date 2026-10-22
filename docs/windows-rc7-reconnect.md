# Windows rc7 reconnect acceptance

Owner rc6 evidence: MetaWise repeatedly needed 15–23 seconds, ending on QUIC;
`connect_switch_ms=1079` measured only the synchronous service command, not the
whole wait for a verified usable exit. Healthy UDP cloud timing did not cover it.

rc7 keeps a live, authenticated core in standby on explicit Off. It first removes
the TUN and verifies its removal, saves Off, and clears the owned WFP rules.
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
is continuously blocked, Off direct traffic with no TUN, fresh HTTP and UDP DNS
after each Connect, remembered failure after core loss, network-hint reset,
missing-guard/wrong-process lease denial, and existing SCM fail-close recovery.
First-ever cold startup, unavailable carriers, long WAN round trips and a failed
network cannot have an unconditional one-second guarantee. Real MetaWise timing
and actual UU sessions still need owner confirmation after cloud acceptance.
This remains unsigned, IPv6 blocked, and not GA.

## First main acceptance evidence and follow-up

Run 39719965235 measured a 402 ms prepared native switch and passed native UDP recovery and QUIC exit/DNS/Off checks. Its first retained QUIC reconnect was 1646 ms, so the strict one-second gate failed and no candidate was published. The relay /32 exclusion expands into many prefixes; Windows route creation was serial. The follow-up build vendors the pinned dependency and applies an exact SHA256-preimage patch to create the same routes with at most four independent concurrent calls, waiting for every call before success or teardown. The full modified source ships in the corresponding-source archive. Reconnect phase measurements are printed for all three strict cycles. No change to prefixes, gateways, routing exceptions, fail-close policy, or the one-second acceptance threshold.
