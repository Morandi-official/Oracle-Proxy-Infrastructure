# R59 — Google HTTPS stages over strict local SOCKS5, no system changes

## Why: R58 field result

R58 was run successfully on the user's actual Windows machine. The
on-screen result: `Google TCP CONNECT 对比：域名 2/2；Oracle 解析的 IPv4
192.178.223.84 2/2。两种 TCP 连接均成功`. The R57/R58 double-provider
Oracle IPv4 egress check also passed. These prove that the R58
SOCKS5 TCP connection establishment was successful in both forms.
They **do not** prove TLS handshake, successful Gmail resource loading
or that Oracle's failed IPv6 outgoing path caused the earlier
browser failures.

## R59 diagnostic

An opt-in `Google HTTPS 诊断` GUI control becomes available only
when the GUI-owned R55 helper reports the local SOCKS5 listener
ready. It makes exactly three unauthenticated, static TLS requests
to public Google endpoints:
- `www.google.com:443` GET `/generate_204`
- `accounts.google.com:443` GET `/`
- `mail.google.com:443` GET `/mail/`

These requests use raw .NET sockets to **127.0.0.1:10880 exclusively**,
send the target hostname in SOCKS5 ATYP=3 (remote DNS), then
authenticate using .NET `SslStream` with normal system certificate
validation and hostname-based SNI. No custom CA, certificate bypass
callback, system proxy or direct fallback is allowed. Read a
bounded HTTP/1.1 response **status line only**, never cookies,
Google account authentication state, mail content or response
body. No redirects are followed. The GUI displays either:
- time consumed by SOCKS5 TCP establishment, TLS authentication,
  and first HTTP status, including actual HTTP response code; or
- which stage was rejected, interrupted or timed out.

R59 retains R57 Oracle IP proof and R58 domain-vs-pinned-IPv4 SOCKS
TCP comparison. These are diagnostic endpoints, not replacements for
a functional Gmail browser session. The GUI never starts Edge,
configures Windows global proxy, WireSock/UU, server routes, WFP,
DNS, firewall or Oracle SSH daemon. Tests are user-triggered and
cancel when Disconnect or close is pressed.

CI uses a **local fake SOCKS5** peer that replies success to a domain
CONNECT, then serves a short-lived **self-signed TLS certificate**.
It asserts that R59's real TLS client refuses the untrusted
certificate, proving that a mock MITM is not blindly trusted.
No actual external Google/Oracle connections happen in GitHub CI.
Existing GUI construction, Windows Job Object kill-on-close, argument
validation, SOCKS reject/no-fallback, address-family packet-format
and route/DNS/firewall baseline tests remain.

## Field acceptance

Do NOT run R58/R59 simultaneously on the fixed port 10880. Disconnect
and close R58, extract the new unsigned R59 artifact into a fresh
folder, and never bypass antivirus or SmartScreen protection to run.
Connect using the existing host, known_hosts and private key
locally, validate Oracle egress, then click `Google HTTPS 诊断` once.
Copy/report the **whole diagnostic dialog**. HTTP 301 or 302 on a
Gmail/login *entry* is a normal redirect, not proof that the signed-in
Gmail experience works. Then disconnect and check UU connectivity.

Full-device WireGuard tunnel, WFP kill switch and UU safe exemption
remain incomplete. This package is NOT a WireSock VPN replacement.
