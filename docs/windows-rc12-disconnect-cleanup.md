# rc12 disconnect cleanup

MetaWise rc11 reported `RECOVERY_REQUIRED` at `DISCONNECT_AUDIT`, with a live
standby native core and no TUN authorization. Disconnect attempted to preserve
the dormant adapter for reconnect speed. Any failed inactivity audit went
straight to recovery, although stopping the owned core and verifying complete
adapter removal could still satisfy the explicit disconnect request safely.

Keep the existing inactivity audit unchanged. If that specific audit fails,
stop the owned core and require the existing complete adapter-removal audit
before saving Off intent or clearing any persistent guard. A failed stop or
failed removal still requires recovery with protection retained. A clean
dormant adapter still preserves warm reconnect. Background error handling
preserves the recovery mode; an explicit preference reset clears old click
and switch timings.

The SYSTEM-only disposable Windows fixture assigns a benchmark IPv4 address
to its own dormant TUN, verifies that the audit rejects it, and checks both a
failed stop retaining the real guard and a successful cold cleanup removing
the adapter before direct traffic is explicitly restored. It also verifies
that a clean dormant adapter does not invoke cold cleanup. This fault never
modifies a physical adapter and the fixture is excluded from the portable ZIP.

This change does not establish MetaWise native UDP reachability. Read-only
Oracle observer run39940229800, attempt2 job120372385990, covered
1792752204–1792752504. The fresh native start1792752291 falls within that
window. Each native port51820/443 recorded19 initiation-shaped arrivals and
19 response-shaped departures, with zero observer socket drops; client
receive counters remained empty. Header-only aggregate counters are timed
correlation, not per-device authentication proof or a complete end-to-end
WireGuard handshake. Current evidence does not identify the failing hop.
