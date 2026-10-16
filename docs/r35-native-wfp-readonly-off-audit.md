# R35 — native BFE read-only preflight and fail-closed off re-audit

R35 adds a real Windows native `fwpuclnt.dll` read-only interrogation on the
actual manager code path, including the LocalSystem SCM startup. The preflight
calls `FwpmEngineOpen0`, `FwpmProviderGetByKey0` for a fixed reserved,
currently non-instantiated provider ID, then frees native allocations and
closes the BFE handle. No mutating WFP, network, service or driver APIs are
called. Ordinary Windows runner self-tests exercise the same native query.

Presence of BFE or the reserved provider is **not** production WFP
attestation: no all-device IPv4, IPv6, per-interface, DNS, boot or crash
coverage is proven. `NativeWfpReadOnlySnapshot` permanently returns false
for `FullDeviceFailClosedVerified`, `MayStartTunnel` and
`MayReleaseFilter`.

The R27 coordinator's *offline* explicit-disconnect transaction now re-audits
the requested WFP policy immediately before attempting to release owned
filters. Negative tests inject WFP failure on the fourth independent audit
(first: connect preflight, second: connected transition, third: off
preparation, fourth: pre-release) and confirm **no Release call**,
latched recovery state and denied future requests. This does NOT make OS WFP,
SCM and disk writes atomic; a real native release adapter is intentionally
absent.

The production `SafeControlGate` still only constructs
`UnavailableProductionKernel`. The existing R21–R30 disposable CI WFP /
native tunnel helpers remain build-isolated, not production capabilities.

## Remaining blockers

A production-ready native provider and genuinely verified system-wide,
persistent filters, protected fixed identity, DPAPI-to-native memory lifecycle
without persistent plaintext, startup rollback, protected route/DNS restore,
real independent packet captures, signed installer and UU compatibility
are all outstanding. Issue #34 remains open; **do not ship or install** this
on critical hosts. No Oracle/WireSock/UU modification is authorized.
