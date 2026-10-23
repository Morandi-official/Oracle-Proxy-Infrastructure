# R10 — default manager excludes privileged experimental lab controls at compile time

Previously, the end-user GUI preview was compiled without CI-only VPN
controls, but the separate manager executable still included its lab-only
administrative pipe implementation and lab flag code. Runtime environment
checks and marker files alone are not a shipping security boundary.

The manager now defaults to **EnableDisposableLabControls=false**:

- `AdminLabControl.cs` and `AdminLabControlSelfTests.cs` are excluded from
  the C# compilation unit in default/release builds.
- Normal SCM entrypoint supports read-only Status and refuses any admin
  lab command, even if CI environment variables are spoofed.
- The in-memory R4 intent model remains offline-only.
- CI builds that actually test paired WireGuardNT test peers opt in
  explicitly at build time with `-p:EnableDisposableLabControls=true`.
- No opt-in lab executable is uploaded or made available as an installer.

Windows cloud CI asserts both independent binary build modes:
default manager rejects admin-service/test flags; explicit CI build retains
only its isolated lab tests. R6 real cloud SCM tunnel lab is rerun with
the explicitly opted-in manager build to avoid breaking valid experiments.

No WFP leak protection, general-connect VPN implementation, signed installer,
recovery-proof claim, independent Internet test or UU acceptance is implied.
Functional Alpha requires a separately audited production authorization
and policy engine, not promoting the lab commands.
