# Authenticated WireGuard HTTPS transport

Caddy exposes only `wss://vpn-admin.morandi.dpdns.org/api/client/relay`.
The separate `oracle-proxy-relay` system identity listens on `127.0.0.1:8788`,
can access only loopback networking and cannot read the admin environment,
database, instance credentials or root policy socket. No new public port opens.
It holds no SSH/OAuth key and accepts no commands or caller-selected destination.

The ordinary device bearer must pass `/api/client/state` before upgrading and
every five seconds afterwards. Disabled, expired, revoked or quota-blocked
accounts close on the next failed check. WireGuard still authenticates/encrypts
each datagram; the existing root-owned wg0 policies enforce device/user limits
on the decrypted tunnel, independent of the transport process. Only loopback
UDP port 51820 is reachable through this relay. Other configured WireGuard ports
are not advertised as supporting HTTPS.

The relay rejects ambient browser cookies/origins, query parameters, nonbinary
messages and invalid/oversized WireGuard frame shapes. It limits active sessions
to 32, one per bearer, queues to 64 packets, and traffic to 4 MiB/s per session
and 16 MiB/s globally; these are resource ceilings, not billing guarantees.
HTTP access logging is disabled, no frame/token/exception body is exported.
Admin quota/accounting remains unchanged; physical VNIC accounting includes
the additional HTTPS overhead. An official Oracle remaining balance is still
unknown until historical coverage and billing units have been reviewed.

Deployment health requires both the existing web application and relay. Upgrade
and rollback restart both; rollback to a version without this relay stops it
and disables its autostart. Returning to a supporting release re-enables it.
The local lifecycle test verifies the separate UID and denial of credential/DB
access. Protocol tests cover real loopback datagrams, token revocation, duplicate
sessions and invalid inputs. An actual Windows-to-Oracle HTTPS WireGuard exit
test is additionally required before distributing a supporting Windows build.
