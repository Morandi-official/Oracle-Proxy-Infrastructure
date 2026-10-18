# R90 — cryptographic provenance is not Windows code signing

R88 added immutable R86 CI-log SHA256 pins and a permanently disabled production signer policy. SHA256 matching establishes integrity relative to a specified CI log; it does **not** authenticate the CI workflow that produced those bytes.

R90 adds a dedicated, branch-restricted disposable Ubuntu Actions test using official `actions/attest@v4`. It creates **one inert text file only** (no EXE, scripts to execute on user computers, keys or VPN components), requests an OIDC-backed short-lived Sigstore provenance certificate, and verifies with `gh attestation verify`:

- exact repository identity,
- exact signer workflow `.github/workflows/r90-provenance-review-only.yml`,
- Git source commit digest,
- authenticated artifact digest with Sigstore-backed verification,
- negative tests for altered bytes and an incorrect workflow signer.

Only successful source identity verification creates the three-day review-only **text** Artifact. Neither the artifact nor its attestation is an Authenticode signature on a Windows EXE/MSI/MSIX installer. No Windows trusted publisher signing certificate, installer, uninstaller, policy-compliant deployment or production GA evidence is created.

## Later legitimate release checks (still blocked)

A future signed release must separately prove actual Windows Authenticode signer identity, externally pinned certificate identity and revocation policy; policy-compliant installer/update/uninstall; intact source provenance verified independently from files inside the package; real reboot/rollback and WFP/IPv4/IPv6/DNS/UU continuity; and independent Issue #34 authorization. R90 is an isolated *proof of provenance mechanics only*, not a signing substitute.

No change to R83 native field activation hard refusal, Windows `UnavailableProductionKernel`, the second PC's execution policy, WireSock/UU, OCI NSG or Oracle `wg0`. Do not treat a successful R90 CI run as authorization to retry blocked unsigned PowerShell scripts.
