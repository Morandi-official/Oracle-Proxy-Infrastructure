# rc26 UU legacy NTFS permission recovery

The rc25 field failure is reproduced on disposable Windows 2022 and 2025 NTFS
volumes: SetSecurityInfo upgrades a legacy DACL's automatic-inheritance format
marker (AI), causing the old byte comparison to reject both apply and rollback.
The normal test initializer had already modernized that marker, concealing the
legacy state. The new non-shipped fixture explicitly constructs that state.

Production retains the documented MAXIMUM_ALLOWED directory handle mode and
SetSecurityInfo; it never uses SetKernelObjectSecurity. It permits only Windows'
one-way AI marker addition for a journal object with a planned mutation. Owner,
group, protection/inheritance switch, every ACE and all other control bits remain
checked. A restore can retain the Windows format marker while restoring the
original access permissions and inheritance switch.

Existing v2 pending/restoring/applied journals remain supported. Recovery also
accepts permutations of identical raw allow-only ACEs (including duplicate
counts), because saved and on-disk order can differ. Any deny, object or callback
ACE disables this compatibility path. Changed rights, owners, identities, links,
volume/source permissions or other descriptor bits still refuse recovery before
writing the journal or any target. Unchanged objects are not rewritten.

The fixture recreates a pending journal with only the first parent modified,
legacy control bits, and reordered allow-only journal entries. It verifies
recovery preserves the source, siblings, runtime data and code descriptors, with
only AI permitted on the written shared ancestors. Deny-order and existing
third-state/file-identity/reparse/metadata tests continue to require zero writes.

Failure diagnostics retain both the original and rollback errors, paths and
control bits in the protected setup diagnostics and the local error dialog.

For an existing rc25 pending transaction: keep VPN disconnected, use rc26
"Restore UU permissions (UAC)" first, and retain the backup. After successful
restore, use "Repair UU permissions and rediscover (UAC)" and then connect.
No UU installation move or data-owner change is required.
