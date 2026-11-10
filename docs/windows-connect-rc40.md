# rc40 connection-path investigation

Baseline: rc39 accepted main42c2a882, actual GUI backend-cold reconnect1319/1294ms, backend-stop700/525ms. Service-ready834/777ms; attested pipe229/250ms. These values are a software baseline, not proof of a hardware floor.

References inspected beyond WireGuard:
- Tailscale [magicsock endpoint](https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go): scoped, expiring path-quality evidence and re-probing; this client already scopes its carrier hints and continues fresh egress validation rather than trusting a stored path indefinitely.
- Xray [core feature/lifecycle implementation](https://github.com/XTLS/Xray-core/blob/main/core/xray.go): construct required features and resolve dependencies before starting them. Use this modular principle to register the emitted product configuration surface instead of every general-purpose sing-box protocol.

Changes: register TUN/SOCKS, direct/nativeUDP/QUIC/HTTPS, WireGuard endpoint and current DNS transports; remove unused proxy, service and certificate-provider registrations. TLS validation in every carrier remains unchanged. Decode all three carrier configurations in real production registries and reject unintended unused protocols. Full Windows network/package acceptance remains required to catch implicit dependencies.

Render diagnostics lazily from a deep-cloned latest snapshot, using StringBuilder, rather than repeatedly concatenating the whole diagnostic text before displaying connection status. Keep the same whitelist, branding normalization and fresh UI timings. Diagnostic formatting does not decide connectivity.

No account-authority interval, binary integrity check, WFP/route ownership rule, dual-stack exit verification or full-backend-Off requirement is relaxed. No zero-RTT authentication/replay tradeoff or persistent backend is introduced. Sub-one-second completion is a target pending real end-to-end measurements, not claimed from inner-service timings.

Local C# Windows-target compile passed. Local Go validation could not obtain the existing compress dependency because the execution environment denies the upstream storage redirect; run the real dependency/configuration checks in the repository Windows CI before merging.

The first main candidate cc20ba65 passed real GUI, browser, dual-family, six-entrance and both package lifecycle checks, but measured full reconnect1386/1344ms (Off646/466ms); registry reduction alone did not establish a speed win and was not released.

Follow-up: race a fresh HTTP/3 trace pair inside the running WireGuard endpoint against the existing SOCKS/HTTPS pair. QUIC removes the separate inner TCP handshake. Both families must complete authenticated TLS1.3 and bounded HTTP200 trace reads. The SYSTEM parent independently checks both expected public addresses, consumes the result once for the current child process, and VpnRuntime still checks its PID/generation, TUN and WFP ownership before Connected. No DialEarly, ticket cache, 0RTT, redirects or account credentials. Fixed1200-byte QUIC packets fit the inner1280 MTU; destination migration is rejected. A silent H3 path has a2s budget; normal HTTPS starts immediately and remains the fallback, including all later periodic probes. EOF cancels/drains the H3 pair before core shutdown. No new background daemon.

New checks cover invalid/duplicate/oversized traces, confined UDP destinations, a real local H3 server with trusted/untrusted/wrong-host certificates, cancellation, parent wrong-family/wrong-exit rejection, success-only racing, fallback, loser cancellation and one-use results. Local C# compile and the standalone shared race tests pass; Go dependency access remains restricted locally, so actual Go/H3 transport tests must pass in Windows CI. Real GUI end-to-end timings must be remeasured after merge; neither a protocol assumption nor service-only timing is a release claim.

Defer only pending-Connect label AutoSize work until the service transaction has started; the last main sample spent37–40ms before dispatch. The command gate/busy flag remains synchronous and final Connected still waits for the verified response. Stop completes even an already-consumed H3 promise so cancellation cannot leave a detached waiter.

H3 follow-up main ea6fc4fc passed real browser/WebRTC/six-entrance and both package matrices. Both GUI cycles used H3. Full reconnect1102/1495ms, Off574/515ms. Core preparation300/850ms dominates the slower cycle; no rc40 release yet.

Adapter follow-up: overlap independently owned sessionless adapter preparation with Box construction/private endpoint startup. Always join preparation on every exit before its ownership cleanup. Fresh native empty-state audit plus an exact, complete DNS-absence snapshot can avoid redundant clearing writes; any ambiguous/failed read or nonempty address/route/DNS takes the existing full cleanup. Never skip the audit on cached Boolean evidence, never open/adopt by name, and keep full Off/backend termination. Add stage timings for process/private-ready/adapter/receipt plus native creation/audit, so OS and application costs can be distinguished rather than called a hardware floor. Add explicit cloud execution of shared proof/deadline regression for the current focused acceptance profile.
