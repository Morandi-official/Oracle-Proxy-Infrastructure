# rc21 delivery and acceptance

The release offers two Windows x64 distributions of the same client, core and
owned WFP boundary: a portable ZIP and a conventional EXE setup. Neither requires
WireSock, the official WireGuard GUI, FlClash or routine SSH operations.

The ZIP can be moved/extracted freely, but its system service must be installed
with administrator authorization before VPN use. The EXE setup manages the
desktop application, shortcuts and Windows uninstall entry, while the existing
protected service installer retains its bundle checks, state protection and
rollback. The two distributions share the machine service and account identity;
they are not separate simultaneous VPN installations.

## Windows trust and prompts

These are distinct mechanisms:

| Prompt | Treatment |
| --- | --- |
| Administrator authorization (UAC) | Required for service/WFP installation, upgrade and system uninstall; normal connect/disconnect remains unprivileged. |
| Unknown publisher | Requires a trusted Authenticode publisher certificate or public-trust signing service. File hashes and the separately signed Wintun driver do not sign our EXEs. |
| SmartScreen download reputation | Trusted signing helps establish publisher identity/reputation but does not guarantee immediate warning-free downloads, including EV signing. |

No workflow disables SmartScreen, antivirus, certificate checks or system UAC.
No self-signed certificate is installed into the user's trusted root store.
When no trusted publisher signing identity is configured, the distribution is
clearly labelled unsigned; it must not claim a verified publisher or guaranteed
absence of warnings. Signing must precede embedded payload hashing and packaging,
and setup signing must precede final release checksums and acceptance of the
exact published artifacts. A future signer therefore needs an authenticated
build integration, not a signature applied to arbitrary files after release.

Official references checked 2026-10-27:

- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation
- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options

## Evidence and limits

The owner's rc20 tests verified native UDP 8443 recovery after core/service
failure and a real Windows restart, with working UU sessions and IPv4/IPv6
WebRTC public candidates equal to the Oracle exits. That is evidence for rc20;
it is not proof that every changed rc21 binary or every earliest-boot packet has
been accepted. Real pre-login traffic observation remains an open gate.

Browser permission tests additionally found physical private addresses exposed
after granting camera/microphone permission. Prompt, denied and revoked cases
did not expose them. VPN routing does not prevent JavaScript from enumerating
local ICE candidates; a machine with native public IPv6 needs its own coverage.

Cloud acceptance must cover both distribution forms, clean install, upgrade,
uninstall, the existing privileged-service boundary and rollback, native UDP /
QUIC / HTTPS fallback, dual-stack policy and real Oracle exit/account linkage.
Only accepted main artifacts may be promoted to the public release and then
mirrored by exact size and SHA-256 to Oracle. All download sources retain the
same bytes and corresponding build sources/licences.
