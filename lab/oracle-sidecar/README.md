# R9 — existing Oracle host sidecar feasibility, strictly read-only

The user currently has only one Oracle production server and cannot create
a separate additional free-tier VM. A potentially viable **later** option
is a *fully independent WireGuard test interface and high UDP port* on the
existing Oracle machine, without changing its current production WireGuard
interface, UDP listener or WireSock peer. Unlike an independent public lab
server, this still **shares machine and cloud-network blast radius** with
production; it is therefore NOT equivalent to the G9 independent-host
recovery requirement.

This PR adds only a read-only Linux inspection. The script:
- Reports whether the WireGuard CLI is installed and whether a presumed
  production wg0 link exists, without reading configs or keys;
- Checks only the occupancy of candidate UDP ports 52911, 52912, 52913;
- Exposes no IP addresses, hostname, instance ID, user, passwords or peers;
- Does NOT use sudo, create keys, modify WireGuard, open cloud ingress,
  install packages, add routes, edit WFP, firewall, DNS or touch systemd.

A candidate with no local UDP listener does **not** mean OCI networking will
accept incoming packets. Cloud security lists/NSGs, independent recovery,
and the production WireGuard listener must be audited separately.
The checker always reports safe_to_enable_oracle_sidecar=false.

## If a human explicitly approves a future sidecar

A reviewed later change would need unique ephemeral keys, isolated new
`wg-alpha` configuration, a separate UDP listener in a controlled high-port,
strictly narrow test /32 and /128 routes, no NAT/default-route changes,
a known working Oracle cloud console/boot-volume recovery, protected key
storage and a timed teardown. It must never reuse or overwrite the existing
production interface/peer or modify WireSock. No such operation is
implemented or authorized by this PR.

## Read-only operator evidence

On the Oracle server's existing Linux SSH terminal, inspect the script
source in the GitHub PR first, then run it with bash and share **only**
its short sanitized key=value output. It does not require root. No keys,
config files, public IPs or credentials should be shared.

CI runs it on a generic temporary Ubuntu runner, not the user's Oracle
machine, and proves only that the probe is non-mutating and returns
self-described unverified safety status. This is not cross-public-network
handshake proof or release readiness.
