# R12: R1 Windows DPAPI and R4 authorized intent planner offline integration

An isolated .NET 8 Windows test executable now links the existing
R4 strict JSON/replay authorization planner and R1 actual Windows
machine-DPAPI intent store, with a conservative bridging coordinator.

Verified properties targeted:
- OS authorization is an injected test value only; unverified callers
  cannot persist an enable.
- An authorized explicit Enable persists and is verified after a new
  coordinator instance simulates a process restart.
- Repeat request IDs are rejected within a coordinator's lifetime.
- A requested Disable is only pending; **no OFF persisted** without a
  future independently proven WFP release and explicit authorization.
- Tampered or unreadable encrypted state quarantines the coordinator.
- Even a syntactically valid old DPAPI Disabled record is quarantined;
  it is not proof that Windows traffic filtering was lifted.
- Every response says physical egress must be blocked, but that actual
  WFP enforcement has NOT been verified; never claim leak protection.

Limitations: no live named pipe or Windows service; no real Windows OS
authorization token is exercised in this bridge; no WFP integration,
packet tests, crash-time pre-boot filter, driver, GUI control, or
network configuration. DPAPI file ACL, rollback/replay across process
restarts, power-loss durability and multi-process locking are not
production-verified. The stored desired state must NEVER be mistaken
for traffic enforcement. No user devices or Oracle server are changed.

R12 does not mark phase 1 or 2 complete.
