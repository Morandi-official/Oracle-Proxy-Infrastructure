# Windows UDP connection latency

The rc38 accepted source f33a1835096f measured real GUI reconnect at 2163/2321 ms and full Off/backend-stop at 677/491 ms on the disposable Windows runner. Both reconnects restored only the same-controller 20-second account proof; every new core independently verified IPv4 and IPv6 egress. This is the baseline, not a one-second result.

The next candidate removes a second AttachClient snapshot/IPC transaction with AttachConnect. The named-pipe server captures the actual client PID and SID before this operation; the runtime attaches that identity under its existing serial admission gate. It performs the same Connect policy, ownership, guard and route checks. It consumes the same generation/PID-bound dual-stack probe task and returns the verified snapshot directly. Failure returns the protected state and normal fallback continues; UI never declares success from the carrier handshake alone. An old service rejects the new command rather than accidentally admitting an unsupported atomic operation.

A private `--standby-probe` core startup mode signals the attested parent when its credential-protected internal SOCKS listener is ready, before preparing the fresh unconfigured adapter. This overlaps fresh IPv4/IPv6 TLS exit probes with adapter creation. The runtime cannot commit Connected until ACTIVATE, actual route ownership and WFP authorization succeed, and the current PID/generation probe succeeds. Other standby/diagnostic protocol paths are unchanged.

The shipped self-contained .NET client uses ReadyToRun to move eligible JIT work to publish time. Service-start polling is reduced from 100 to 20 ms. Control I/O resumes outside the UI synchronization context. Local control response timings separately record service readiness, attested-pipe readiness, and full response latency. No account proof expiry is extended, background core retained after Off, image hash/ACL verification skipped, or TLS/IPv6 exit validation removed.

References studied (implementation concepts, no upstream source copied):

- [WireGuard Windows manager notifications](https://github.com/WireGuard/wireguard-windows/blob/master/manager/ipc_client.go): the client receives tunnel-change notifications instead of waiting for an unrelated periodic status refresh.
- [WireGuard Windows service tracking](https://github.com/WireGuard/wireguard-windows/blob/master/manager/tunneltracker.go): Windows service change notifications drive state changes.
- [.NET ReadyToRun](https://learn.microsoft.com/en-us/dotnet/core/deploying/ready-to-run): precompile eligible managed code to reduce startup JIT, with a larger published payload.

Acceptance uses the real Proxy.exe UI, fresh backend/core restarts, verified dual-stack exits, two complete on/off cycles, and X cleanup. Report end-to-end GUI measurements, not just the inner Connect RPC time. A target below one second is a goal; publish only measured results and keep first/expired-account startup distinct.
