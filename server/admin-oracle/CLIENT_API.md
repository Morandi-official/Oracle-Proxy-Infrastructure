# Native account authentication and explicit device confirmation

The website is administrator-only, using the configured fixed local administrator credentials (GitHub/MFA mode is a separate optional configuration). VPN accounts cannot authenticate administrator APIs. Administrators assign credentials, quota, expiry and a device cap (default3); no public signup exists.

## Client flow

1. `POST /api/client/authenticate`: exact JSON `username,password,public_key,device_name,client_version`. The public key is generated and retained by the Windows SYSTEM service; no private key leaves the device. Correct credentials create a hashed bearer session, not a Peer. A pending session expires after15minutes, consumes no device slot and receives no tunnel configuration. Account quota/expiry and a bounded list of that account's own devices are readable.
2. Show the local computer name, editable device nickname, short public-key fingerprint and slot count. Require an explicit ownership checkbox and the action “确认并登记此设备”.
3. `POST /api/client/enroll`: bearer plus exact JSON `device_name,confirm:true`. The server selects the account and key from the session, rechecks revocation/active policy and calls the root controller's fixed `peer.enroll`. The root daemon serializes the cap check and registration. Existing same-account keys are idempotent and occupy no extra slot. Another account's key, an unmanaged key or a revoked key cannot be adopted. The confirmation timestamp/machine label/client version are durably recorded in the root ledger.
4. Only a confirmed device receives a tunnel. Windows independently checks confirmation before preparation or Connect; disabling the GUI button is not the authorization boundary. Relays also require an authorized registered device.
5. `GET /api/client/state` refreshes quota, expiry, current-device confirmation and own-device names/fingerprints. `POST /api/client/presence` accepts only fixed mode/transport enums and returns the same state. Presence is advisory; it cannot enable a Peer, override policy or set usage counters. `POST /api/client/logout` deletes the bearer and records an audit event; registration and usage remain.

Bearer routes reject cookies and Origin headers, use HTTPS and no-store responses, accept no arbitrary destination/RPC/command, and share persistent password-throttle counters. Credential changes invalidate sessions. Enrollment and management transitions share a lock and revalidate the bearer before root mutation. Pending sessions are bounded, and no passwords/tokens/private keys are displayed in device lists or audits.

## Identity, limits and surveillance

The identity is a device-local WireGuard key, with a12-hex-character display fingerprint; it is not a hardware serial/MAC identifier. Copying the portable GUI does not copy the protected service key. Reinstalling Windows or clearing keys creates a new identity. Re-login/upgrade with the same key reuses the existing registration. Physical-machine attestation or resistance to cloning an entire privileged Windows installation is not claimed.

The client shows all active devices (at most32 by policy) and at most8 revoked history records. The administrator sees all managed Peers, account association, confirmation timestamp, machine label/version, recent API contact, self-reported client mode, independent WireGuard handshake and independently collected usage. Client-reported state and handshake timestamps are explicitly distinct; neither is treated as definitive application traffic or billing evidence.

## Compatibility and rollout

Existing pre-upgrade bearer sessions continue using already authorized Peers, avoiding mass disconnection during server rollout. Their records are labelled legacy until explicitly confirmed in the new client. New authentication uses the pending/confirmation flow. Legacy `/api/client/login` never creates a Peer and returns `CLIENT_UPDATE_REQUIRED` for unknown or unconfirmed keys; it cannot bypass confirmation by creating a new device. After confirmation, the old endpoint can authenticate that already confirmed identity.

Root receipts survive logout and web-session deletion. Reassigning a Peer to another account invalidates the old owner's confirmation; the new owner must confirm. Revocation is permanent for that public key and preserves usage/audit tombstones.
