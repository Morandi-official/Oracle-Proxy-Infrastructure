# W3 — simulated control API and crash-safe *model*

This adds a **pure C# state machine**, not an installed privileged service.
It is intentionally not reachable from another process. It makes no Windows
API calls, does not use WFP, never connects to Oracle, cannot start WireGuard,
and does not save the user's intent.

The only accepted test-only user commands are `EnableVpn`, `DisableVpn`,
`Connect` and `DisconnectTunnel`. A fake `mockCallerAuthorized` flag is
supplied by the test harness. **It is not real authentication** and cannot
be treated as a security boundary in production.

## Model invariants

- Unknown/undetermined intent defaults to deny direct traffic in the *model*.
- A mock verified connection requires `Connected`, fresh handshake and
  verified tunnel path all simultaneously.
- Connecting, stale, failed, crashed, and disconnected states never silently
  change a mock Enabled intent to Off.
- Disconnecting a tunnel alone never permits ordinary physical direct egress.
- Direct networking returns in this model **only after an authorized explicit
  `DisableVpn` command**.
- UU exceptions are mock-identity-gated, as is the Oracle IPv4/UDP transport
  exception. Name-only identity is not adequate for production.

## CI

Run `OracleProxy.Windows.Preview.exe --control-self-test` (Windows hosted VM).
This validates policy state transitions and a matrix of IPv4/IPv6,
TCP/UDP/DNS, tunnel/physical egress and mock UU identity inputs.

## Real requirements NOT met

- Protected and persistent user intent across boot and power loss.
- Windows service authenticated IPC, elevation, service ACLs and SID/signer
  verification; a test-supplied Boolean can never replace them.
- Actual WireGuard client, real handshake verification, DNS and IPv6 controls.
- Real WFP policy ordering, boot-time enforcement, crash safety and UU P2P.
- Independent local recovery before deploying any network block to the live PC.

Use this module to test design assumptions only; it creates **no real fail
closed behavior**. Do not deploy or activate filtering on the UU-controlled
Windows PC based on these passing tests.
