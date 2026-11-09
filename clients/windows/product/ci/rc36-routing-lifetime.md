# rc36 ordinary routing and desktop lifetime

The rc35 core SOCKS probe could pass while Windows selected the physical `/0`
for ordinary apps. The owned WFP policy then correctly refused that direct path.
The TUN now advertises IPv4 and IPv6 split defaults, leaving all physical and
third-party route entries untouched. Unbound GetBestRoute2 queries must select
this TUN in both address-space halves before authorization/Connected. Connected
state is rechecked when routes change; core egress alone cannot certify it.

Explicit Disconnect cold-stops the core and prewarm. After its verified Off
response is written, the SYSTEM control service stops normally; the window stays
open and stops polling. The registered desktop owner has only SCM query/start
rights, allowing the next deliberate action to restart the fixed service without
UAC. GUI commands still authenticate the pipe server against SCM before sending
credentials. The installer handles a self-stop in progress.

AttachClient records an OS pipe peer PID, creation time and authenticated owner
SID inside SYSTEM DPAPI state. No caller-provided PID is accepted. Confirmed death
of the last attached GUI triggers the same audited Off transaction. Access/query
uncertainty does not mean death. Network/core failure with the GUI alive retains
failclosed protection. An unremembered login resumes across intentional service
stops only while that same GUI process identity is still alive; final GUI death
forgets it. Installer/observer Status calls do not create GUI owners.

Main acceptance uses a disposable Windows runner with physical interface and
route metrics zero (restored in finally). It checks ordinary HTTP/DNS, native
route selection, actual ordinary Edge navigation to ipcece, BrowserLeaks and the
public privacy page, ICE public candidates, controller process death, service
stop and reconnect. Browser page loading is not a claim that remote captcha or
site account login succeeded. No ICE public candidates is explicitly inconclusive.
No browser direct bypass, TLS-ignore option, third-party process stop or global
firewall reset is used. Logs export fixed outcomes, not browser contents or keys.
