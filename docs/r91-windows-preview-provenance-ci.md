# R91 — Cryptographically attest the exact unsigned Windows read-only preview

R90 verified GitHub OIDC/Sigstore provenance for inert text only. R91 extends the subject to the existing read-only Windows preview EXE, built from this PR's immutable commit on GitHub-hosted Windows. CI never uploads, installs, signs or distributes the executable.

## Trust boundaries

1. Build OracleProxy.Windows.Preview.csproj with EnableDisposableLabControls=false. Exact output allowlist accepts the preview EXE and optional PDB only, never WireGuardNT engine, manager SCM binary or installer.
2. Windows Get-AuthenticodeSignature must independently report NotSigned. Signed GitHub provenance is not Windows Authenticode.
3. Official GitHub actions/attest@v4 signs short-lived GitHub/Sigstore provenance for exact EXE bytes. An independent gh attestation verify call requires the expected repository, signer workflow and source commit digest.
4. Altered EXE bytes and unrelated signer workflow must be refused.
5. No Windows binary is uploaded as GitHub Artifact or offered to a user. R86 SHA256 fingerprints are not changed and no physical execution is authorized.

## Remaining blockers

No trusted Windows publisher certificate, hardware-protected signing key, signed installer/uninstaller, update rollback, physical reboot recovery, independently verified WFP fail-close across IPv4/IPv6/DNS, UU live continuity, genuine public cross-host native tunnel or GA authorization is implied.

R83 runtime native field activation remains hard-denied. Production UnavailableProductionKernel remains denial-only; Issue #34 stays OPEN. No Oracle wg0, OCI NSG, user Windows, WireSock/UU, VPN/WFP/route/DNS or Windows PowerShell execution-policy changes.
