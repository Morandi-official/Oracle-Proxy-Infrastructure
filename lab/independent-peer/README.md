# Independent VPN lab endpoint (G9) — NOT Oracle production

This directory implements a **configuration and recovery prerequisite** for a
separately owned, disposable Linux server and Windows lab client.

**It does not provision an external VM, open UDP ingress, activate WireGuard,
alter Windows routes, or connect to any Internet host.** There is currently no
independent external server attached to CI. Passing GitHub CI means the
configuration restrictions and recovery checklist work, **not** that a real
cross-network VPN handshake was performed.

## Required independent environment

A separate Linux VM, not the existing Oracle instance, with:
- a dedicated *public IPv4* endpoint that is NOT `152.67.156.100`;
- an external/hypervisor console and a tested pre-change VM snapshot;
- permission to receive only lab UDP `52901`, no production firewall edits;
- a separate Windows VM with a tested out-of-band recovery console;
- two new WireGuard keypairs, neither reused from existing WireSock/Oracle.

Provisioning is **blocked** until these prerequisites exist and the user
has approved this disposable lab. We cannot create a cloud VM, bill an
account, or guarantee that a GitHub Windows runner can receive/connect to a
separate GitHub Linux runner from the current repository. CI runners are not
a substitute for a publicly reachable independently controlled lab peer.

## Configuration generator

`generate_configs.py` uses Python 3.12 standard library. On the **Linux
lab server** supply the server private key only via a protected on-disk file,
and the **Windows lab client public key** over an authenticated channel.
Generate the server config in a fresh secure directory using the role
`server`, and the Windows config separately using the role `client`.
The latter takes the **client private key** (on the Windows lab only),
the public server key and the independent public IPv4.

Use `--dry-run` for schema validation; it does not write config files or
contact any peer. Actual staging needs an explicit, existing empty output
filename and `--lab-confirm INDEPENDENT_VM_WITH_CONSOLE_AND_SNAPSHOT`.

Outputs include ONLY:
- server interface `10.249.134.1/32`, UDP listen 52901;
- client interface `10.249.134.2/32`;
- allowed remote peer /32, never `0.0.0.0/0` / `::/0`;
- endpoint public IPv4 of the independent VM, never Oracle production;
- no DNS, scripts, system proxy, firewall rules, or auto-start changes.

No part of CI runs `wg-quick up`, `ip route`, `iptables`, Windows SCM,
WFP, or remote SSH. No key or config is uploaded as an artifact.

## True cross-network acceptance (not yet met)

With operator-controlled VMs and an *independently restored VM snapshot*
ready, the lab must first confirm a UDP path between two **different VMs**.
Then, and only then, start the *narrow lab WireGuard profile* and read real
`latest-handshakes` / transfer counters at both ends. Test repeated reconnect,
stale key/endpoint, service crash, reboot and teardown with before/after
IPv4/IPv6 routes and DNS captured.

Failure to supply an independently accessible host, a real packet capture,
an authenticated server identity, and out-of-band recovery is a **blocker**,
not an invitation to connect to the user's production Oracle instance.

## Leak/UU testing is a distinct safety gate

Read `lab/recovery/README.md`. Only a separate, noncritical Windows VM
with a verified recovery console is eligible for any WFP experiment.
Successful external handshake does **not** prove IPv4/IPv6/DNS fail-closed,
nor that genuine UU P2P traffic remains direct.
