# rc17 ordinary protocol selection retains native UDP8443

Owner rc16 failure diagnostics showed native_udp.preferred_port=0, native_udp_dual_port and only51820/443 initiation counters, then QUIC fallback. Selecting the ordinary UDP menu sent PreferUdp, which discarded the existing fixed8443 override. The diagnostic8443 button is a preference setter, requires disconnected intent, and does not itself connect. These semantics made a working daily native transport look broken.

Owner then disconnected, selected the fixed8443 action and connected without reselecting the ordinary protocol. The same rc16/server/hotspot completed native UDP8443 with a handshake reply, oracle_egress_verified, no read/write/obsolete errors and606ms click-to-ready. No server queue rollback or MTU/crypto/buffer change is justified by this report.

The authenticated service now exports the capability boolean native_udp_8443_available. GUI ordinary UDP selects the existing fixed8443 command when advertised; Auto uses a new fixed PreferAuto8443 command, preserving automatic fallback semantics. Before Connect, the GUI resolves a default/legacy port selection to8443 only when disconnected, supported and not already selected. A rejected selection cannot fall through to Connect. No passive status poll changes active intent. Existing prepared8443 cores stay warm.

The service independently rechecks its own server-advertised capability for both fixed8443 commands. The GUI capability is not authorization. No arbitrary ports, commands, destinations, keys or settings are accepted. The test button is disabled while connected/connecting, and stale instructions about reselecting UDP to exit the working path are removed. Legacy service protocol commands remain available for backward compatibility and cloud51820/443 loss fixtures.

Validation covers actual WinForms selection/click dispatch, Auto/UDP default Connect ordering, failed-selection refusal and connected button state; real Oracle acceptance adds the fixed Auto preference then retains full native8443 stability and legacy port/loss/fallback tests. Server configuration is unchanged.


## Accepted release evidence

Main sourcefa3ee556e5d0e2ef7f51f1dfc10153df69923a53/run40080860124/job120833945309 passed complete Windows and real Oracle acceptance. Actual WinForms ordinary UDP reselection/default UDP+Auto Connect/refusal cases passed, as did real advertised Auto8443 preference. Native8443 low-MTU stability lasted120535ms; disposable peer usage2751956bytes, registered devices27. All legacy/native/QUIC/HTTPS, service recovery, fail-closed, usage linkage and quit/logout checks passed. The initial PR disposable synthetic-core startup failed once; the identical source passed on retry, with the GUI regressions passing in both attempts.

Public rc17 BUILD/source/checksums were independently verified against that accepted run. Client SHA2565c480d61add3d50b1b7fec526b84370d55bfefb585445fa317a858b87fa22dae. Oracle mirror pins all four exact public assets and keeps older versions. No transport/server rollback or new bandwidth improvement is claimed.
