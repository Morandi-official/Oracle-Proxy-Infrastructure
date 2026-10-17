# R83 — valid field lease MUST NOT authorize real native WireGuardNT activation

R81's compile-time isolated `EnableAttendedFieldTrial` diagnostic host accepted a protected time-bounded field metadata lease, including a `operator_confirmation_recorded` JSON boolean. That field is **not an authenticated consent record**. R82 independently proved Windows SYSTEM Task Scheduler could expire OFFLINE test files, but it explicitly refuses an active native service. A real native tunnel must never start on the basis of only those two successful tests.

## Hard runtime gate

`FieldTrialRuntimeLease.Require(config)` is called from the actual `OfficialTunnelBridge.InvokeFromService` via `NativeLabInnerScopeGate` **before LoadLibraryEx and any native device/network change**. R83 splits the harmless `ReviewScopeOnly` from privileged `Require`: even if config hash, Admin/SYSTEM NTFS ACL, public endpoint, /32 inner AllowedIPs, keys, expiry and self-asserted consent fields are all accepted for offline review, privileged `Require` explicitly **throws / rejects activation**. The diagnostic compiler flag does not relax that runtime gate. Default production compilation still entirely excludes `lab-field` and refuses the service CLI.

Windows CI compiles both normal and explicitly opted-in diagnostic host binaries, verifies the normal build refuses the field service and even the diagnostic CLI, creates an exact protected synthetic R81 field config (never a user key nor real Oracle listener), then shows valid offline review success and real service activation refusal. No DLL is loaded and no tunnel service, driver, WFP filter, route or DNS setting is changed. Exact owned fixture cleanup remains enforced.

## Conditions to safely remove this deliberate blocking gate

1. An independently validated SYSTEM-owned watchdog that **actually stops an active, exactly owned field native SCM service** on lease expiry, including interface and route cleanup, does not depend on GUI/manager processes, and handles mid-activation failure. The R82 offline deletion watcher is not sufficient.
2. Crash and reboot recovery safety with a physically supervised Windows rollback plan, and demonstrably no residual plaintext key/config after restart. A GitHub live-OS one-shot scheduling test is insufficient.
3. Independent operator consent/authorization that cannot be granted merely by editing a boolean in the protected metadata. Approval for Oracle ephemeral wgtest and approval for native changes on the physical second Windows PC must be separately obtained before any live action.
4. Signed/pinned installer binaries, protected credentials, and controlled WFP fail-closed behavior for the intended product traffic scope, independently evaluated on real IPv4/IPv6 and DNS and with UU remote continuity. R68 official-client tunnel success does not prove these for our native client.

Until those gates are completed, production manager `UnavailableProductionKernel`, release gate Issue #34 and disabled native field connection remain unchanged. **R83 improves denial, it does not claim live public connectivity.**
