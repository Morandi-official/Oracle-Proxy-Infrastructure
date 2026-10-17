# R77 — GitHub-hosted Windows single-peer protected staging & deletion

## Context

R76 CI now constructs a single reviewed WireGuardNT candidate profile in memory with exact IPv4-only tunnel target. This R77 stage validates the next prerequisite: a temporary private-key-bearing file under Windows Admin/System NTFS scope, without starting any real tunnel or contacting Oracle.

## On one ephemeral Windows GitHub runner

- Require `GITHUB_ACTIONS=true`, runner environment `github-hosted`, Windows OS and explicit `ORACLE_R77=CI_ONLY`. The source and scripts never run on the user's second Windows computer.
- Refuse if the dedicated `ProgramData/OracleProxyR77Only` directory, native test service or future inner route already exists. Create the empty directory, then install a protected DACL admitting **only BUILTIN Administrators and NT AUTHORITY SYSTEM**, with explicit inheritable access for the single test file.
- Only after that secured-directory setup, create an exact job-owned marker. A Python helper generates a new ephemeral X25519 client private key in memory and one synthetic, NOT user/Oracle, external-IP proposal. It runs R72/R76's narrow scope and reciprocal key validation, writes one `lab-peer-a.conf` using exclusive creation and flush, and verifies the data without printing or uploading its private key.
- The parent PowerShell script independently inspects the directory, marker and file DACLs for any untrusted principals, and checks that Windows default IPv4/IPv6 routes, DNS servers, firewall rule count and lab SCM service state remained unchanged.
- Even on test failure, an `always()` step removes **only** the exact two expected owned files and this one empty directory, refusing any symlink, foreign marker or unexpected resource. An independent final step confirms no native service or new inner route exists.

## Boundaries

The file is **plaintext while staged**. Admin/System ACLs are necessary but insufficient for production key safety. R77 does not provide persistent DPAPI/LSA memory protection, crash-safe shredding, a signed binary, reboot recovery, an actual SCM tunnel, an OCI listener, all-process WFP no-leak or live UU continuity. The cloud test keys are never copied to the physical Windows PC or committed to GitHub.

The next required gate is an independent single-peer native SCM *offline* loader safety review that combines the protected ephemeral config with verified official DLL hashes and expiry recovery. Any actual Oracle NSG/firewall changes and test Windows driver/service installation require **new, separate user authorizations**. Production `UnavailableProductionKernel` continues refusing connection; GA Issue #34 remains open.
