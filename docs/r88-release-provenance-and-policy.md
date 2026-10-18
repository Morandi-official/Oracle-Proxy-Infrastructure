# R88 — independent artifact pins, OS signature boundary and safe Windows delivery

**Evidence scope:** source-only validation and actual Windows Authenticode **read-only signature-status queries** on disposable GitHub Windows CI. No installer is built/signed, no user computer is touched, no PowerShell execution-policy changes, and no Oracle/WireGuard/WFP/UU changes.

## Trust levels (keep them separate)

1. **CI log SHA256 matched:** the external seven-file R86 digest mapping from Windows CI run \`39044333007\` (artifact ID \`12105571201\`) can establish byte correspondence to that specific CI output. It is **not** an Authenticode chain, verified GitHub provenance, or permission to execute. The package's own \`SHA256SUMS.txt\` is explicitly untrusted.
2. **Windows Authenticode:** Windows must validate the actual executable/installer's Authenticode signature at install time, with reviewed, independently pinned publisher identity and revocation/timestamp policy. A Windows-signed third-party binary is NOT automatically our product. R86 scripts and mock remain **unsigned**.
3. **Independently authenticated build provenance:** future signed artifacts need a verifiable link to an authorized workflow, immutable repository revision and protected CI signing identity, validated **outside the package**. A locally editable \`"signed": true\`, hash manifest, CI variable, action log string, or caller bool is no attestation.
4. **Deployment authorization:** the real signed installer/rollback path additionally requires independent GA #34 approval, real Windows consent, OS policy compliance, recovery and UU coexistence proof. No signer pin exists yet: production remains hard-denied.

## New defensive code

\`release/r88_artifact_policy.py\` is deliberately **read-only**; it checks an exact allowlisted package shape, independently supplied lower-case SHA256 pins, ordinary files only, no linked directory or extra payload. It carries the historical seven R86 CI digests, but does not fetch, launch, approve or distribute that artifact. \`production_release_verdict\` has source-controlled empty allowlisted publisher thumbprints and release-enable=false; even every self-asserted trust input being true is refused. The Windows runner also reads each R86 script's Authenticode status and proves \`NotSigned\` without changing policies.

Negative regression coverage: tampering while rewriting the in-kit digest list, missing file, extra payload, nested directories, reparse/symlink root where supported, unsafe names, malformed hex pins, and spoofed production trust values. No artificial positive signer identity is invented.

## Policy-compliant future operator delivery

- Do not rerun the blocked R86 script or recommend \`-ExecutionPolicy Bypass\`, \`Set-ExecutionPolicy\`, \`Unblock-File\`, disabling SmartScreen/Defender, renaming script files, or invoking an alternate interpreter to bypass the current policy.
- Evaluate a separately reviewed **genuinely signed**, user-visible, native Windows package with Authenticode validation plus enterprise policy compatibility; code signing may **still not** satisfy App Control or every local policy. The correct response to a block remains **stop and report**.
- Any installer must do a no-mutation preflight, verify exactly owned services/tasks/files and authorized signer, register independent recovery **before** driver activation, and uninstall only owned resources. A reboot/restart-safe service cannot be inferred from the three-minute R86 mock.
- The signed Windows publisher certificate, signed installer, trusted build attestation, product-grade policy, true reboot recovery and physical UU/WFP/DNS proofs **do not yet exist in this milestone**. This development alone authorizes neither R86 rerun nor new physical/Oracle actions.

**R83 must continue to refuse native field activation**. Production \`UnavailableProductionKernel\` and open GA Issue #34 remain unchanged.
