# rc18 explicit device ownership confirmation

New client login authenticates an administrator-issued account and returns a pending device identity without allocating a Peer, consuming a slot, starting a core, or disclosing tunnel configuration. The user reviews the local device name and short key fingerprint, edits a recognizable name, ticks ownership confirmation and explicitly registers. The service uses its own protected key and bearer for a fixed enrollment operation. Connection requires the returned server confirmation and fresh active policy, independently of the GUI. Registration alone does not enable VPN routing.

The existing account cap defaults to three. Enrollment and account changes are serialized, Root enforces the cap, and confirming an already allocated same-owner device does not allocate again. Revoked identities and identities owned by another account cannot be adopted. Existing pre-upgrade sessions retain their old access during rollout, but the new client requires an explicit receipt for legacy devices. A fresh login in an old client cannot automatically enroll.

The client displays only the signed-in account's device names, short identifiers and current-device marker, retaining pending text/consent during status polls. The administrator sees pending sessions, confirmed device ownership/name, first confirmation time, recorded machine/client version, recent advisory presence, actual handshake and measured usage. Presence never authorizes a tunnel or sets billing. There is no MAC/serial collection or claim of hardware attestation.

Backend PR227 passed 40 Django, 20 root policy and 22 relay tests locally, both Python CI versions, actual Chromium/Firefox management UI tests, disposable lifecycle/control checks and production migration/deployment. Client acceptance adds actual WinForms pending/consent/name-preservation/cap cases and a real Oracle pending login -> rejected Connect -> explicit confirmation -> idempotent re-confirmation sequence, retaining the full UDP8443, QUIC, HTTPS and fault acceptance suite. Release acceptance results are appended only after the actual run passes.

Native UDP8443 selection, stable MTUs, core transport code, socket buffers and server queue configuration are unchanged. This remains an unsigned candidate with the broader boot/IPv6/signing acceptance limitations documented in the product README.

## Accepted release source

Source41169fd6fca86815d67d7566bdc45c4cfcbacaa1, main run40088627377/job120856554605 passed the complete Windows and real Oracle acceptance. Actual WinForms consent/name preservation/slot checks, aligned layout and unchanged idle-poll rendering passed. Real authentication stayed pending without a core/slot; the service rejected Connect and registration without consent; explicit confirmation allocated exactly one slot and repeated confirmation was idempotent. Native8443 low-MTU stability lasted121903ms. The dedicated acceptance account had29 registered devices, below its separate32-device test cap. Ordinary accounts still default to three.

Backend PR227 is deployed; client PR228 and portable-instruction PR229 are merged. Publication uses only the exact accepted source/client artifacts, with draft-first release validation and independent public metadata verification before Oracle mirroring. Broader signing/boot/IPv6 acceptance remains open.

Public rc18 BUILD and checksum metadata were independently downloaded and matched to accepted source/run and all four public asset digests. Client SHA25681309dc205d4924920e0ad43c70fc080d7c56c30409d290961d1d71d24289bf6. The Oracle mirror pins the same complete asset set and retains earlier releases.
