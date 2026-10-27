# rc22: self-contained .NET 10 LTS client

The portable ZIP and conventional EXE setup now target `net10.0-windows`.
Both bundle the reviewed .NET runtime, so the user does not need a machine-wide
.NET installation. Upgrading replaces the desktop executable and fixed SYSTEM
service together; it preserves the existing Windows owner, DPAPI-protected
account/device identity, and server-side registration. Do not uninstall first.

## Version and support policy

The release starts with SDK **10.0.403** and runtime **10.0.14**, checked against
Microsoft's .NET 10 release metadata on 2026-10-27. The channel is LTS and its
published end-of-support date is **2028-11-14**. The SDK is pinned in
`clients/windows/product/global.json`; the shared runtime and first-party package
versions are pinned in that directory's `Directory.Build.props`. Production,
fault-test and bad-upgrade projects use the same runtime policy.

This updates the Windows .NET host and fixed adapter lifecycle without changing
WireGuard packet processing, Oracle endpoints, traffic restrictions, device
limits or the login protocol. It adds
no updater service, heavy packer, runtime download at application startup, or
machine-wide runtime dependency. Native DLLs retain their protected, explicit
loading paths; no broad DLL search-path compatibility bypass is introduced.

Cold cleanup uses a successful native `GetIfTable2` query as its absence proof.
Any `OracleProxy` row remains present, including `Down` or other inactive states;
query errors also fail closed. Managed interface descriptions remain diagnostic
metadata and cannot by themselves certify device presence or absence.

A successful fresh TUN creation records its fixed GUID, native LUID and creator
PID/start time in a small SYSTEM/admin-protected receipt. Normal creation no
longer adopts an existing adapter by name. Crash recovery requires the receipt
to match the current native identity, the recorded creator to have exited, no
other live product core, and active fail-closed protection. Only the pinned core's
fixed recovery mode may flush that verified adapter's own IP/routes/DNS and
complete its Wintun lifecycle; it cannot select another interface, arbitrary
command or executable. Unknown receipts, foreign GUIDs and live creators remain
rejected. No driver deletion or global PnP cleanup is introduced. Protection is
kept until native enumeration proves the adapter is absent; the existing
three-second absence audit remains in force after bounded orphan recovery.
Recovery failures retain a bounded, sanitized helper reason code for diagnosis.

An explicitly disconnected prepared core has a separate fixed dormant recovery
mode. It requires the existing protected encrypted OFF state, no recovery flag,
no active guard or TUN permit, the same creator receipt and a verified exited
creator. Independent native queries must find a Down interface with no routable
configuration, both before and after obtaining
a fresh creator handle. The only address exception is Windows-generated IPv6
link-local with WellKnown prefix origin, LinkLayer/Random suffix origin and a
/64. Associated routes require the native Local protocol and an unspecified
next hop; destinations are limited to those exact /64s, audited address /128s
and ff00::/8. Windows' exact IPv4 224.0.0.0/4 and 255.255.255.255/32
routes are also permitted only with native Local protocol and an unspecified
IPv4 next hop. IPv4 addresses, other IPv4 destinations, manual origins,
default routes and custom gateways are refused.
A successful complete DNS-adapter snapshot must agree with that identity and
Down state when the target LUID is present; ambiguity or a query error is refused.
Windows may retain default/inherited DNS servers and suffix metadata on a Down
interface. This metadata grants no authorization, is never used as a route or
destination, and is not interpreted or migrated by the helper. Its presence does
not prevent disposing of a receipt-owned, inactive, non-routable interface while
the protected persisted intent is explicitly OFF. This makes no claim about
registry settings and never changes another interface's DNS configuration.
This mode never flushes IP/routes/DNS, starts a packet session or changes WFP.
It only closes its own fresh creator and still requires native absence proof.
Dirty or unknown interfaces are rejected. Ordinary applications remain direct
during OFF preparation; old verification and pending-probe generations are
invalidated before cleanup, including when cleanup fails.

Self-contained does **not** mean permanently maintenance-free: an installed
shared .NET security update cannot replace the runtime inside an old application
bundle. A supported new runtime patch must be incorporated into a new product
release, pass the existing Windows/Oracle acceptance gates and be installed by
the user. The weekly read-only runtime check flags newer stable .NET 10 patches,
SDK updates and an approaching channel end-of-support. It has no Oracle or
account credentials and cannot merge or deploy changes. NuGet Dependabot retains
its bounded update PRs. Neither mechanism authorizes an untested automatic
production upgrade or a silent jump to a new .NET major version.

## Compatibility and verification

The shipped client is x64. Windows 11 is the primary current desktop target.
Microsoft's current .NET 10 supported-OS matrix lists only Windows 10 editions
and servicing channels that remain in support; general Windows 10 22H2 is not
made supported again by changing .NET. Older Windows technical compatibility and
the operating system's own patch/ESU/LTSC eligibility are separate questions.

Release verification must include:

- The **actual published executable** passes its runtime-version assertion even
  with the shared-runtime lookup directed at an empty directory.
- Resolved framework packs, runtime configuration, SDK and package versions are
  recorded in `BUILD.json`; packaging rejects mismatches and .NET 8 runtime packs.
- Real WinForms rendering/idle-layout, SCM-authenticated IPC, SYSTEM DPAPI,
  protected extraction cache, WFP/driver loading, recovery and failed-upgrade
  rollback continue to pass.
- Live adapter creators and invalid/foreign ownership receipts must be rejected
  without changing the adapter or guard. The actual one-shot SYSTEM recovery
  must remove a receipt-owned hard-kill orphan and preserve the device key.
- An OFF prepared-core hard kill must recover an empty owned orphan without
  installing a guard or interrupting ordinary TCP/DNS. A real dirty prepared
  interface must be refused by both the parent's live-creator check and the
  independent native audit without losing configuration or receipt. After
  creator death, a remaining dirty state must still be refused; Windows' own
  removal of the injected address is reported only after native audit and
  final interface absence succeed.
- A digest-pinned rc21 .NET 8 payload is installed on a disposable Windows runner
  and upgraded in place. A synthetic, account-free SYSTEM DPAPI state is used;
  the test must retain its owner/device key identity rather than enrolling a new
  real device.
- The main-only ordinary test account verifies native UDP, QUIC, HTTPS fallback,
  dual-stack Oracle egress, policy linkage and safe disconnect. Both final
  distribution forms must pass their respective acceptance before publication.

These are release gates, not a claim that a test has already passed. The public
release links to the successful main workflow for its exact source revision.
Earlier physical reboot evidence remains version-specific; earliest/pre-login
full traffic observation and trusted publisher signing remain separate limits.

Official references:

- https://dotnet.microsoft.com/en-us/platform/support/policy
- https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json
- https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md
- https://learn.microsoft.com/en-us/dotnet/core/deploying/runtime-patch-selection
- https://learn.microsoft.com/en-us/dotnet/core/compatibility/interop/10.0/native-library-search
