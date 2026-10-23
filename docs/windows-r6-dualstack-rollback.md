# R6 dual-stack tunnel rollback regression on disposable Windows CI

This test extends the G17 genuine WireGuardNT Windows laboratory.
It captures a Windows pre-tunnel snapshot of default IPv4/IPv6 routes,
DNS server settings and Firewall rule count. It refuses preexisting
synthetic IPv4/IPv6 routes or test peer adapters.

It runs genuine Windows SCM+GUI-controlled temporary dual-stack tunnels
and UDP/DNS application probes, then independently attempts to stop/delete
the two owned tunnel services, remove throwaway keys and configs, and
verify these four scoped routes are absent:

- 10.249.129.1/32
- 10.249.129.2/32
- fd42:14::1/128
- fd42:14::2/128

It also checks no test peer adapters or fixed peer SCM entries remain,
and compares route/DNS/firewall baselines. Temporary CI-only ingress rules
must have been removed. Any difference fails CI.

A passing R6 is **reversible narrow-route lab cleanup** only.
It does not validate Windows WFP fail-closed, physical default-route VPN,
boot recovery, UU direct network access, separate public hosts, or
production installation. It must never run on the UU-dependent PC.
