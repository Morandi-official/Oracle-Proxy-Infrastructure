# Oracle Proxy 0.3.0-rc26

Fix custom-drive UU permission maintenance when Windows upgrades a legacy DACL format marker. Recover existing v2 pending backups with full object-identity and permission checks; preserve mutable config/log/setup data owners and ACLs. Error dialogs retain original and rollback failure details.

For a pending rc25 transaction, disconnect VPN and use Restore UU permissions (UAC) in rc26 before repairing again. Keep the backup.

Portable ZIP and Windows setup EXE. Self-contained .NET 10 LTS; unsigned prerelease.
