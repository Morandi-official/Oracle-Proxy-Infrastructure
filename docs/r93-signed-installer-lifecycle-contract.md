# R93 — code-signing readiness and fail-closed Windows installer lifecycle

**Status: SOURCE-ONLY REVIEW; NO SIGNED INSTALLER OR PERMISSION TO INSTALL.**

R88 fixed an empty approved-publisher allowlist, R90 verified GitHub Actions source provenance for inert text, and R91 demonstrated independently verified GitHub/Sigstore origin of a genuinely compiled **unsigned** Windows read-only preview executable. R89 proved exact-owned SYSTEM-native stop/cleanup in a disposable Windows CI without actual reboot. R92 requires independent real-reboot/WFP/UU evidence and never auto-authorizes a release.

R93 adds a static *lifecycle safety contract* (`release/r93_installer_contract.py`) and negative tests for a future product-grade signed installer/uninstaller. It **does not** stage, install, sign, run, uninstall or publish software, acquire a certificate or change Windows policy. `main-source-safety.yml` now independently queries the current read-only manager/preview EXEs with actual Windows `Get-AuthenticodeSignature`, requires that they are still `NotSigned`, and rejects unexpected MSI/MSIX or private key material under the current non-GA build. If legitimate code signing is introduced later this guard will fail for deliberate security review, not silently treat a change as production approval.

## Cryptographic identity and delivery requirements (not implemented)

A future product publisher certificate must be associated with an authorized legal publisher identity, purchased/enrolled **only after operator authorization**, protected in hardware-backed custody or a reviewed signing service, with least-privilege build-to-sign delegation. No certificate/private key may be stored in the repo, CI logs, GitHub artifact, unsigned manifest or shared VM image.

A release-signing process must, before distribution, independently check real Windows Authenticode validity on the exact signed EXE/MSI/MSIX and uninstaller, signer certificate chain to an approved Windows root, purpose/Code Signing EKU, issuer/publisher policy, source-pinned signer identity, timestamp validity, revocation status, byte-exact artifact hashes and independently verified GitHub build provenance. Plan for certificate rotation/revocation and a blocked fallback if an expected publisher changes. GitHub Sigstore provenance alone cannot remove SmartScreen, Defender, App Control or PowerShell policies; a Windows signature is not guaranteed to be permitted on every managed endpoint.

The current repository has **no approved publisher thumbprint or signed installer/driver**. A self-declared `signed:true`, `release:true`, `claims:all_passed`, altered local digest manifest or CI environment variables are never a trust root.

## Exact-owned installation order and safe-Off recovery

The R93 contract requires read-only OS policy assessment, independent out-of-band recovery verification, real Windows code-signature and provenance verification **before** staging, recovery registration and proven persistent all-device WFP guard **before** any native activation, followed by actual IPv4/IPv6/DNS and UU monitoring.

The inverse uninstall is not simple reverse file deletion. It must retain the guard; stop **only this app's owned native service**; independently establish safe native Off; restore exact-owned route/DNS state and durably record explicit Off; re-audit WFP/egress/UU; only then conditionally release **only provably owned** WFP filters; verify recovered network/UU; clean owned tasks, services, files and keys; and revoke test credentials.

The source tests reject wrong operation order, wildcard or foreign third-party resources including WireSock/UU, omitted recovery owner, fake signature metadata and incomplete or stringified proof claims. **Even all self-declared proofs true return denial**. The actual production kernel is still `UnavailableProductionKernel`, and R83 field activation remains refused.

## Limits

This work neither replaces production WireSock nor proves signed software installation, actual reboot, WFP pre-login leak prevention, cross-host public WireGuard, real UU continuity, or cert revocation infrastructure. Actual acquisition of a real Windows code-signing identity, creating a recoverable noncritical test VM, configuring a separate external peer, touching Oracle, or running on the second PC each requires prior independent authorization where applicable.

GA Issue #34 remains OPEN; do not bypass Windows execution policies or ship R86 unsigned scripts as a trusted installer.
