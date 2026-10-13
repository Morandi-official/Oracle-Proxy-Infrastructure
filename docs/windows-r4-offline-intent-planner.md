# R4 — offline authorized VPN intent transition planner

This is a **pure in-memory design/test class** compiled into a .NET Windows
manager binary, but not instantiated from either the normal service, GUI,
Windows named-pipe status handler or the CI-only tunnel control handler.

Only the opt-in command `--offline-intent-planner-self-test` exercises it
with synthetic OS token decisions. No real identity is authorized by a client
boolean; future production use must impersonate the named-pipe client with
an actual Windows token and verify approved user/signer policy.

The model starts at `UnknownFailClosed`, accepts explicit simulated user
Enable, rejects forged identities and unsupported operations, deduplicates
request GUIDs, and keeps the Enabled intent after disconnection, handshake
staleness or process crash observation. An explicit Disable is represented
only as a **pending request**. There is intentionally no public or internal
`CommitOff` implementation because no real WFP enforcement release or
rollback-resistant durable OFF state can be demonstrated.

## Scope and limitations

- No Windows service, tunnel driver, DNS, route, WFP filter, registry or
  persistent file is touched by the test.
- `physical_egress_block_required=true` denotes an **obligation**, not actual
  traffic blocking. `actual_wfp_enforcement=false` always.
- A fresh object representing process restart becomes Unknown, not Off.
- Real persistence needs DPAPI+protected ACL+anti-rollback and commit ordering;
  Windows WFP must actually enforce across crash/boot/IPv4/IPv6/DNS before
  this can be integrated with any production privileged service.
- This R4 does not make a working VPN, permit replacing WireSock, validate
  UU P2P or satisfy production release evidence.
