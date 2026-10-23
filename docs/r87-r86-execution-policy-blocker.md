# R87 — R86 second-PC PowerShell policy refusal (no physical test started)

**Status:** `PHYSICAL_R86_BLOCKED_BEFORE_PREFLIGHT` on 2026-10-18 (UTC+8). This records operator-reported field evidence; it is not a test pass or authorization for new operations.

## Scope and evidence

- R86 [PR #116](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/pull/116) merged as `d35f949892d0a450b91f3891d3ad9627ad08c469`. Disposable [Windows CI #39044333007](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39044333007) succeeded for a non-network running SCM mock with an independent SYSTEM scheduled stop; [postmerge security CI #39044766628](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39044766628) succeeded. Neither establishes physical acceptance or live WireGuardNT safe-Off.
- Official GitHub Actions artifact `R86-SECOND-PC-NO-NETWORK-REVIEW-ONLY`, ID `12105571201`, expires at `2026-10-24T15:21:32Z`. It contains seven unsigned review files and a separate `SHA256SUMS.txt`.
- The operator on the second Windows PC compared seven file SHA256 values with the independent CI-log values: `R86_ALL_7_HASHES_MATCH_CI`. Matching hashes prove integrity against the referenced CI output, **not** trusted Authenticode signature or permission to execute.
- First attempt: `R86-Preflight.ps1` was rejected by Windows PowerShell **before the script body executed**: `PSSecurityException`, `FullyQualifiedErrorId : UnauthorizedAccess`, with the OS indicating script execution was prohibited. No `R86_PREFLIGHT_PASS`.
- No `R86-Start.ps1`, test service, SYSTEM stop task, real VPN, network change or `R86-EmergencyCleanup.ps1` execution was reported in the supplied transcript. This is **not** a remote inventory of the physical PC.

## Fail-closed response

1. **Stop the physical R86 sequence**. Do not run Start, Verify or Cleanup scripts as a workaround for a blocked preflight. The recorded commands never reached a mutating R86 step. Any independent indication of preexisting resources requires a separate precise-identity investigation, never broad deletion.
2. Do not instruct the operator to disable Defender, SmartScreen, firewall, UAC or the PowerShell execution policy, or to use `-ExecutionPolicy Bypass`, `Set-ExecutionPolicy`, `Unblock-File`, alternate hosts, or renamed script extensions to circumvent policy.
3. The R86 mock and PowerShell scripts are **unsigned review-only** files. Do not advertise a signed Windows installer, and do not regenerate this artifact under its prior seven-file SHA256 manifest.
4. Already granted authorization covers only the original supervised **no-network** R86 exercise. A new artifact/deployment method or any physical native driver, Oracle/OCI, VPN, WFP, DNS, route or firewall change requires separate review and, where applicable, separate authorization.
5. A safe future distribution path must honor the machine's existing controls. Investigate genuinely trusted signed delivery **or** an independently audited, policy-compliant non-PowerShell operator path. Merely signing PowerShell cannot override a policy that prohibits all scripts; obtaining trusted code signing and actual field compatibility evidence remains outstanding.

## Acceptance gates remaining

`R86_PHYSICAL_PREFLIGHT`, `R86_PHYSICAL_SYSTEM_AUTOSTOP`, `R86_EXACT_CLEANUP`, and `R86_PHYSICAL_UU_AND_WEB_CONTINUITY` remain **unproven**. Also unproven: live WireGuardNT safe-Off, reboot recovery, IPv4/IPv6/WFP/DNS packet leak controls, signed installer/uninstaller and production replacement.

R83 must continue to refuse native field load, production `UnavailableProductionKernel` stays enabled, and GA issue [#34](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/issues/34) stays OPEN. R87 CI only audits source/policy documentation: **no field execution, no new operator artifact, no native networking or OS mutation**.
