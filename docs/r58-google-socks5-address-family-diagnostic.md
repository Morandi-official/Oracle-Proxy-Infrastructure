# R58 — Google SOCKS5 hostname-vs-Oracle-IPv4 diagnostic (not a VPN)

## Operator-reported evidence

The Windows test operator verified R57's two independent IPv4 exit-IP
checks, both HTTP 200 from Oracle public IPv4 152.67.156.100. R57
Connect and Disconnect buttons passed on the physical computer. A
separate Microsoft Edge SOCKS5 profile was able to open Wikipedia,
but intermittently failed to load Google/Gmail. Several repeated
curl "timeouts then success" were traced to Windows PowerShell's
legacy handling of the empty `--noproxy ""` argument, **not**
legitimate target failures; subsequent corrected commands with
`--noproxy localhost` returned Google connectivity HTTP 204
and Gmail HTTP 301 with exit code 0.

Later, independently repeated curl requests through R57 **did**
time out for Google sign-in and Gmail at 8 seconds, with HTTP 000 and
exit 28. A read-only SSH command run **on Oracle itself** returned
Google HTTP 302 through `curl -4`, while `curl -6` returned
exit 7 (cannot connect). An operator's
`curl --proxy socks5h://127.0.0.1:10880 --connect-to`
request to Oracle-resolved Google IPv4 returned HTTP 302 and exit 0.

This is strong evidence that explicit IPv4 can work through the
SOCKS5 tunnel and the server's IPv6 path is presently failing.
It is **not proof** that the SSH remote DNS address family is the
root cause of the intermittent browser failure; no SSH remote
address-selection trace was captured, and a single pinned request
does not establish reliability.

## R58 change

Keep R55's proven SSH SOCKS5 implementation and R57's explicit exit
IP verification **unchanged**. Add an opt-in button on the GUI:
"Google 双栈诊断" (Google address-family diagnostics).

This optional diagnostic:

1. Requires an already-running GUI-owned SSH SOCKS5 connection,
   verified SSH key file and local known_hosts.
2. Performs two raw SOCKS5 TCP CONNECT attempts on the
   **existing** localhost-only listener to
   `accounts.google.com:443` using SOCKS5's hostname target.
3. Runs a **fixed, read-only**, separate Windows OpenSSH command on
   the user's existing server, with strict host-key validation:
   `getent ahostsv4 accounts.google.com`. It parses one server-side
   IPv4 A answer. This command does not modify Oracle DNS, IPv6,
   routes, firewall, SSH services or other configuration.
4. Performs two raw SOCKS5 CONNECT attempts to the returned IPv4
   literal on destination port 443, without changing the browser's
   behavior or DNS resolution policy.
5. Compares success counts and displays a **limited diagnostic**
   conclusion with explicit caveats: raw SOCKS5 TCP CONNECT success
   is NOT equivalent to Gmail HTTPS success; a difference in success
   counts is not proof the hostname attempt used IPv6.

All probes have short cancellation deadlines; GUI Disconnect/window
close cancels the diagnostic and stops only its child R55 and
strictly owned read-only SSH query. No direct TCP connection to the
Google destination occurs from the Windows computer: only loopback
SOCKS5 and the already trusted Oracle SSH host are touched.

The disposable Windows CI only tests the SOCKS5 packet encoding via
a fake localhost TCP server which sends a synthetic success. It
checks domain ATYP 3, IPv4 ATYP 1 and network-port bytes, plus existing
R57 fake SOCKS5 no-fallback checks, GUI constructor, job cleanup,
and Windows route/DNS/firewall baseline. No live Oracle host, user
private key, or real Gmail request is used in CI.

## User field acceptance when convenient

Do not run two GUI versions on the same SOCKS5 port simultaneously.
Close and disconnect R57, download R58 unsigned WinForms CI artifact
only if permitted by Windows security (never disable SmartScreen),
extract the whole ZIP, then connect with the previously verified
SSH credentials. Press the existing "验证 SOCKS5 出口" to reconfirm
Oracle IP. Then press "Google 双栈诊断" once and report the exact
result. Observe that it performs only connectivity probes and **does
not promise to make Gmail work**.

This remains application-level SSH SOCKS5: no complete WireGuard
tunnel, WFP leak prevention, driver, installer, auto system proxy,
IPv6 protection or tested UU production network exemptions.
GA issue #34 remains open.
