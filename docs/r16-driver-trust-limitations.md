# R16: runtime Windows Authenticode verification of native WireGuardNT

The existing signed upstream WireGuardNT 1.1 DLL SHA-256 and vendor archive
pins are verified in CI. R16 adds an OS-local WinVerifyTrust check *inside the
elevated Windows tunnel service host*, after the manifest integrity and
SYSTEM/Administrator-owned protected NTFS ACL preflight and before LoadLibraryEx
ever receives the original DLL path.

The CI-only negative test takes the exact signed upstream DLL (SHA-256 pinned),
verifies trust, verifies the same bytes copied under a different protected
temporary file location, and rejects an unsigned file and a copy altered
inside signed PE content. The real disposable Windows SCM test also repeats
the actual WireGuard handshake through the signed-driver runtime gate.
No private key or signed binary is uploaded as a Release artifact.

**Limits**: Authenticode local verification checks Windows trust, not the
specific upstream signing identity alone. The exact official SHA pin still
matters. The runtime uses cached trust without an online revocation check,
because VPN boot must not depend on a network connection. The upstream
embeddable tunnel.dll is built from a pinned source revision in CI but is
not yet signed for distribution; runtime trust for *that* DLL still requires
a separate release-signature policy. A signed DLL plus ACLs and hashes is
not a secure installer, encrypted key vault or kernel WFP kill switch.

Current lab configs may contain synthetic ephemeral WireGuard private keys
in protected plaintext until the tunnel stops. Production needs reviewed
DPAPI/private-key lifecycle, key rotation/revocation, signed installer and
verifiable cleanup before anybody installs a functional client.

No Oracle instance, WireSock or UU application is accessed. Issue #34 remains
the publication blocker. The Windows CI proofs do not establish end-user
functional Alpha or cross-network public transit.
