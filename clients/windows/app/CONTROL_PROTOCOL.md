# W4 — bounded offline control request validation

This is **only a deterministic protocol parser and mock authorization gate**.
It does **not** create a Windows service, IPC pipe, socket, driver, firewall
rule, WireGuard tunnel or configuration file. It never changes an OS setting.

## Accepted request envelope

UTF-8 JSON, maximum 1,024 bytes; exactly three fields:

```json
{
  "protocol_version": 1,
  "request_id": "c23f7f33-996b-4c6c-859f-027e1f68e2c6",
  "command": "EnableVpn"
}
```

Permitted command names, matched exactly and case-sensitively:

- `EnableVpn`: mock user enables VPN intent; enters Connecting
- `DisableVpn`: explicit mock user intent Off; only this permits direct
- `Connect`: mock transition to Connecting only while intent Enabled
- `DisconnectTunnel`: mock tunnel stops; user VPN intent does not change

Unknown, duplicate or missing fields, malformed JSON, wrong protocol versions,
invalid GUIDs, integers instead of command names, oversized frames,
replays and mock-unauthorized calls are denied. No path, endpoint, key or
shell command can appear in the envelope. A bounded replay set returns denial
rather than silently dropping protection.

The `mockCallerAuthorized` Boolean is supplied by test code and is **NOT**
a substitute for actual Windows impersonation tokens, authenticated IPC
ACLs, service identity, signed caller validation, secure storage or OS WFP
enforcement. Nor is its replay set persisted across process restarts.

Run in a GitHub-hosted Windows VM with the native preview CI and
`OracleProxy.Windows.Preview.exe --protocol-self-test`.

## Mandatory engineering gates before real service/engine

- Separate privileged service binary with explicit Windows Service SID
  and tightly scoped local IPC ACL, refusing untrusted identities
- Validate caller identity **from OS tokens**, not a bool or process name
- Integrity-protected persisted user intent, boot-time fail-closed design
- Independent local recovery and on-site rollback before filter installation
- Verified and licensed WireGuard embedding implementation, separate
  real handshake/path/IPv6/DNS checks and noncritical lab peer
- WFP app/endpoint/interface arbitration tests including UU UDP P2P

The live Oracle and UU Windows host are not touched. No passing simulation
test establishes actual VPN connectivity or IP leak protection.
