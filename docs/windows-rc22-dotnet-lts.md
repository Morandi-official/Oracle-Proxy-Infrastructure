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

This changes the Windows .NET host, not WireGuard, the Go packet-processing core,
Oracle endpoints, traffic restrictions, device limit or login protocol. It adds
no updater service, heavy packer, runtime download at application startup, or
machine-wide runtime dependency. Native DLLs retain their protected, explicit
loading paths; no broad DLL search-path compatibility bypass is introduced.

Recovery cleanup distinguishes an operating-system `NotPresent` interface
description from an installed tunnel device. Historical descriptions of a
removed device do not keep recovery blocked; `Up`, `Down`, `Dormant`, `Testing`,
unknown and all other present states still block cleanup. The three-second
cleanup bound, owned-interface checks and protection rules remain in force.
Recovery failures retain a bounded, sanitized helper reason code for diagnosis.

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
