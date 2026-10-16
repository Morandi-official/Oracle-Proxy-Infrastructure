# R48 — CI SYSTEM-owned all-application WFP + DPAPI native tunnel coexistence

R48 extends the real R47 LocalSystem SCM-to-native-WireGuardNT handshake
integration with an independently scoped **persistent** Windows Firewall/
WFP outbound rule installed by the actual SYSTEM service process BEFORE the
lab's synthetic WireGuard adapter begins running.

The policy affects only four fixed, public resolver destination addresses:
`1.1.1.1`, `8.8.8.8`, `2606:4700:4700::1111` and
`2001:4860:4860::8888`. It applies to all applications, protocols,
Windows firewall profiles and interface types for those fixed addresses.
It does NOT alter default routes, system DNS configuration, existing
third-party rules, or the remainder of Internet connectivity.

On the disposable Windows runner the packet verifier:

1. Proves TCP 443 and raw UDP DNS are independently reachable at selected
   fixed destinations **before** SYSTEM installs any WFP policy.
2. Starts an exact demand-only LocalSystem manager which installs this
   narrowly scoped COM-backed WFP policy, queries the current OS-owned
   scope, then launches R47's genuine native DPAPI in-memory
   WireGuardNT handshake as a SYSTEM child.
3. Independently reads active Windows Firewall dimensions and requires
   actual TCP/UDP DNS requests to be denied at previously reachable
   IPv4 destinations. If IPv6 lacks an external baseline it explicitly
   prints `NOT_PROVEN` rather than claiming IPv6 packet success.
4. Stops the fixed SCM manager. The SYSTEM-created persistent rule remains
   until **after** tunnel stop. Cleanup verifies exact rule ownership/
   protocol/direction/program scope before removal, and then requires
   TCP and UDP DNS to become reachable again.
5. Requires exact stage/SCM cleanup and unchanged default IPv4/IPv6 routes,
   DNS configuration and all unrelated Firewall rules.

A non-disposable runner and default production binary cannot access this
mode. Any mismatched, preexisting or modified rule must not be overwritten
or removed. All temporary artifacts are on a one-off cloud runner that
GitHub destroys regardless of the outcome.

## Still NOT a full-device fail-closed VPN

The policy is deliberately **not** 0.0.0.0/0, ::/0, or all physical
Internet. Four fixed resolver IPs do not prove unrestricted TCP/UDP/DNS,
boot-time persistent filtering, endpoint identity/exceptions,
UU remote-control compatibility, traffic on new interfaces,
atomic OS route/WFP handoff, independent external captures, or
crash recovery. R48 is a real and useful *narrow* integration test,
not a production Windows WFP kill switch. The normal manager continues
to use `UnavailableProductionKernel` and GA blocker #34 stays open.

No Oracle server, real WireGuard profile, existing WireSock, UU or user
Windows network is modified.
