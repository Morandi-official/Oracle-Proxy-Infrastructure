# R57 — Native GUI SOCKS5-only HTTPS exit verification

## Physical user finding

The user confirmed that their ordinary Microsoft Edge continued to load
Baidu before and after clicking R56 "连接应用级代理", while opening
`https://api.ipify.org/` directly in normal Edge failed both times.
**This does not prove an R56 proxy outage.** R56 intentionally never
modifies the Windows system proxy or the existing normal Edge profile.
The user's earlier explicitly SOCKS5-configured Edge instance had
returned their Oracle public exit IP and loaded Wikipedia, and R55
and R56 CLI tests had returned IP-echo HTTP 200 with one reported
intermittent timeout. Their R56 "断开代理" action was followed by
no listening socket at `127.0.0.1:10880`.

## R57 change

Add an explicit "验证 SOCKS5 出口" button next to Connect / Disconnect
in the same opt-in user-mode R56 GUI. The button is disabled until the
owned R55 helper reports exact local-listener readiness. It never
changes the Windows, Edge, WireSock, UU, firewall, DNS, routes or
SSH service settings.

When the user presses Verify, R57 creates a **new isolated
`HttpClient` instance** with a hardcoded local
`socks5://127.0.0.1:10880` proxy and `UseProxy=true`. The .NET 8
SOCKS5 connection passes the target hostname to the SOCKS server; it
must not fall back to direct connections when the SOCKS5 proxy fails.
The verifier sequentially performs HTTPS GET to exactly:

- `https://api.ipify.org/`
- `https://checkip.amazonaws.com/`

Each request has a deadline; redirects are disabled and the response
is length-limited. Neither endpoint's response is considered successful
unless HTTP 200 and an actual IPv4 address is returned. Both responses
must match. For an input SSH host expressed as an IPv4 literal, the
verified external address must additionally equal that input; DNS
hostnames require an independent owner-of-IP check. Failed providers,
mismatched addresses or timeouts do not report "verified". A
successful check proves application-level SOCKS5/HTTPS egress only,
**not** full-device protection or browser traffic routing.

A dedicated GitHub disposable-Windows `--proxy-path-self-test` uses
a fake localhost SOCKS5 server which explicitly rejects CONNECT and
checks that the SOCKS5 client sent a target hostname instead of
resolving it locally. The fake server never forwards traffic or
accesses the public network. A SOCKS refusal must not silently
succeed through the host's direct internet connection. Existing
real Windows GUI construction, child-kill, argument injection and
route/DNS/firewall inventory checks remain mandatory.

## Next field acceptance (user controls timing)

Stop R56 before trying this new test, and don't run the two versions
concurrently: the port is intentionally fixed. Download the new
unsigned R57 GitHub CI artifact only if permitted by OS protection;
never bypass SmartScreen or antivirus.

Enter the same locally known SSH host, username and existing private
key (never upload or paste key contents), press Connect, then press
"验证 SOCKS5 出口". Report the whole status text. If either provider
times out, the GUI must show **not verified**. Click Disconnect,
confirm the local listener disappears and normal Edge + UU remain
unaffected.

R57 is a browser/application-level encrypted SSH SOCKS5 proxy,
**not** a full device VPN/WireGuard alternative; WFP leak prevention,
IPv4/IPv6 full coverage, UU exempt policy and release issue #34
remain open.
