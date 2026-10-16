# R49 — Process-crash WFP quarantine (disposable Windows CI)

R48 established that a real LocalSystem SCM manager can install a narrow,
all-application fixed-destination Windows Firewall/WFP block before
running the synthetic R47 DPAPI-to-native WireGuardNT handshake, and that
TCP and UDP DNS traffic to those exact public test addresses are denied.

R49 tests a different failure mode: **a manager process is killed without
running its graceful OnStop cleanup**.

On an ephemeral GitHub Windows machine, after the native two-peer handshake,
the workflow strictly matches its demand-start LocalSystem SCM registration,
fixed `--ci-fixed-destination-wfp` startup args and exact manager binary path
before forcibly terminating only that service process. It requires:

- The SCM to recognize the service has stopped.
- The persistent, OS-backed, application-independent four-target rule to
  remain installed and continue rejecting *new* real IPv4 TCP/UDP DNS
  probes; external IPv6 is claimed only with a successful pre-block baseline.
- An attempted restart while that owned rule already exists to **fail
  closed** rather than silently adopting an ambiguous, preexisting rule.
- The OS-level block to remain effective after this denied restart.
- Exact deletion of the test service and ONLY its own fixed WFP rule,
  followed by regained TCP/DNS reachability and restored IPv4/IPv6 route,
  DNS, Firewall and temporary adapter baselines.

This does NOT make crash recovery safe on a real user's PC: persistent
on-boot WFP guarantees, broad IPv4/IPv6 physical interfaces, dynamic
network changes, DNS routing and UU remote control still need design,
actual enforcement, independent external capture and recovery approval.
A short GitHub runner failure cannot prove no transient packets escaped.
The production manager's `UnavailableProductionKernel` remains blocked.
No Oracle, WireSock or UU changes. GA issue #34 stays open.

If the test detects an unexpected SCM identity or executable, it refuses
to kill that process. Any fail-closed result does not automatically
authorize VPN connection or a production WFP release.
