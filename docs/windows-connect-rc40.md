# rc40 connection-path investigation

Baseline: rc39 accepted main42c2a882, actual GUI backend-cold reconnect1319/1294ms, backend-stop700/525ms. Service-ready834/777ms; attested pipe229/250ms. These values are a software baseline, not proof of a hardware floor.

References inspected beyond WireGuard:
- Tailscale [magicsock endpoint](https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go): scoped, expiring path-quality evidence and re-probing; this client already scopes its carrier hints and continues fresh egress validation rather than trusting a stored path indefinitely.
- Xray [core feature/lifecycle implementation](https://github.com/XTLS/Xray-core/blob/main/core/xray.go): construct required features and resolve dependencies before starting them. Use this modular principle to register the emitted product configuration surface instead of every general-purpose sing-box protocol.

Changes: register TUN/SOCKS, direct/nativeUDP/QUIC/HTTPS, WireGuard endpoint and current DNS transports; remove unused proxy, service and certificate-provider registrations. TLS validation in every carrier remains unchanged. Decode all three carrier configurations in real production registries and reject unintended unused protocols. Full Windows network/package acceptance remains required to catch implicit dependencies.

Render diagnostics lazily from a deep-cloned latest snapshot, using StringBuilder, rather than repeatedly concatenating the whole diagnostic text before displaying connection status. Keep the same whitelist, branding normalization and fresh UI timings. Diagnostic formatting does not decide connectivity.

No account-authority interval, binary integrity check, WFP/route ownership rule, dual-stack exit verification or full-backend-Off requirement is relaxed. No zero-RTT authentication/replay tradeoff or persistent backend is introduced. Sub-one-second completion is a target pending real end-to-end measurements, not claimed from inner-service timings.

Local C# Windows-target compile passed. Local Go validation could not obtain the existing compress dependency because the execution environment denies the upstream storage redirect; run the real dependency/configuration checks in the repository Windows CI before merging.
