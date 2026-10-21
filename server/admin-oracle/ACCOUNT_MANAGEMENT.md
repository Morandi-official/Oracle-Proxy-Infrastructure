# Administrator account lifecycle and official usage

Only the configured GitHub administrator with recent OAuth and MFA can use `/api/control`. Native client credentials never grant dashboard access. The single user form saves display name, client username/password, quota, expiry, enabled state and device limit (default 3). A blank password during editing preserves the hash. Password/username changes invalidate bearer sessions; disabling the user or revoking a device stops tunnel traffic.

Deletion tombstones the root policy and revokes every attached public key before removing credentials/sessions. Users disappear from the active list; accounting, addresses and audit history remain. Revoked public keys cannot enroll again, including after controller restart. Recreate a user with a new identity and new device keys. Changes across the web credential database and root policy ledger stage access disabled; a partial failure leaves a disabled row that the administrator can edit and retry. Saving does not reset usage.

The independent `oracle-proxy-oci-usage.timer` queries official APIs every 15 minutes. It uses short-lived instance-principal authentication; no API private key is requested, saved in GitHub or exposed to the web application. The probe is bounded separately from the 5-second kernel lease loop. Its root-only cache contains structured observations and non-secret resource identifiers for IAM setup. Raw exceptions, IMDS certificates and tokens are never logged. Web/collector systemd units deny access to the IMDS credential endpoint.

Monitoring queries `oci_vcn.VnicToNetworkBytes[1h].sum()` for attached VNICs, from UTC month start through completed hours. VNIC metrics include internal traffic and traffic before drops. They are not a billable internet-egress balance. Usage API rows retain SKU and units for review; absent rows and pagination never imply zero usage. Unverified coverage and billing delays leave the remaining allowance unknown; the probe does not silently overwrite a manually confirmed baseline or enable budget enforcement.

When instance-principal authentication is available but API access is denied, create an Oracle dynamic group matching **only this instance**. The administrator dashboard shows the resource identifier. Grant only `read metrics` in the subnet's compartment, conditioned on `target.metrics.namespace='oci_vcn'`. Cost Analysis additionally needs tenancy-level `read usage-report`. Do not grant tenancy management or account write permissions. Changes to IAM must be performed by the tenancy owner; server root is not equivalent to Oracle IAM authority.

References:
- https://docs.oracle.com/en-us/iaas/Content/Network/Reference/vnicmetrics.htm
- https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm
- https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm
