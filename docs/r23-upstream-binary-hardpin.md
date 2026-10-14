# R23: hardcoded upstream WireGuardNT runtime pin

The real Windows SYSTEM WireGuard service now refuses any DLL whose SHA-256
does not equal the compiled-in SHA-256 of the reviewed upstream WireGuardNT
1.1 AMD64 official DLL. The existing Authenticode WinVerifyTrust chain
verification, protected NTFS ACL gate, and per-bundle SHA-256 integrity
manifest all remain mandatory.

The previous mutable engine-pins.json manifest protects against accidental
file corruption but a privileged actor could rewrite the manifest for a
different signed DLL. The newly compiled constant cannot be changed without
changing/rebuilding the service executable; this is stronger defense in
depth, especially after a signed installer locks down service binaries.

Cloud Windows tests use genuine upstream bytes, independent-copy verification,
an unsigned DLL, a single-byte changed DLL and a *different signed Windows
system DLL*, and demand refusal of all substitutes. A separate disposable
Windows SCM test starts genuine WireGuardNT peers to prove real tunnel
compatibility with hardcoded pinning.

**Limitations:** a machine administrator able to replace/recompile service
code is outside this protection, and the upstream source-built tunnel.dll
still needs an independent, signed release provenance policy. Version updates
must undergo an explicit pinned-hash code review and full Windows CI rerun.
No production binary, key vault, whole-device WFP, independent public WAN
or UU assurance is claimed. Oracle and second PC are untouched. #34.
