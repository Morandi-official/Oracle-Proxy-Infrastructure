# R36 conservative SYSTEM restart boundary

This stage adds an **offline deny-only startup recovery contract** and
exercises it during a real LocalSystem SCM manager startup. All persisted
states, including `OffRecordedNeedsOsAudit` and `ConnectedRecorded`,
explicitly deny unattended tunnel start, physical direct traffic enablement,
or WFP filter release. Missing/corrupt/incomplete journal states demand
out-of-band audit.

The constructor `ReadConservativeBaseline` queries the real BFE read-only
preflight from R35, then deliberately records no positive security evidence.
The live manager does not read a production journal or automatically repair
a machine. Tests cover all six journal phases and individually missing
system evidence. This is a *safety contract*, not a working production
recovery controller. The R32 DPAPI durable journal remains CI-only in a
separate project and is not passed off as production persistence.

No production backend activation, WFP filter installation/release, network
routing change, Oracle changes or third-party VPN/UU modification occurs.
The only permitted live manager is the default `UnavailableProductionKernel`.
Do not remove GA blocker #34 on the basis of this phase.
