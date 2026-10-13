# Production GA evidence requirements

**There is currently no evidence manifest and no approved production release.**

The static checker in this folder intentionally exits nonzero while
release/ga-evidence.json is missing. It verifies paths/digests only; it
cannot verify real packet captures, legal rights, Windows signing
certificates, production recovery, independent external hosts or UU
remote-control continuity. Thus even a checker exit 0 is NOT authorization
to publish a usable VPN. Release signing, provenance, review and approval
must be independently demonstrated.

The nine mandatory evidence categories are defined in check_evidence.py.
Do not fill them with synthetic flags or cloud CI-only proof. In particular,
localhost peer counters, an open WFP/BFE handle and offline DPAPI logic
are not successful fail-closed, live UU or cross-Internet validation.

Until all real critical gates pass, GitHub preview artifacts must remain
clearly labelled unsigned, read-only, not VPN and NOT GA.
