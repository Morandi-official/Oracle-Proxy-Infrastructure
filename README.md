# Oracle Proxy Infrastructure

Oracle-hosted VPN service, administrator-only web console and independent Windows
client. Current distributions are **unsigned acceptance candidates, not a GA
release**. The Windows product embeds its WireGuard/TUN core and uses an
authenticated SYSTEM service for everyday connect/disconnect; no WireSock,
official WireGuard GUI, FlClash or daily SSH commands are required.

- [Windows portable ZIP and standard EXE releases](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/releases)
- [Product source and acceptance boundaries](clients/windows/product/README.md)
- [.NET 10 LTS runtime, upgrade and maintenance policy](docs/windows-rc22-dotnet-lts.md)
- [Oracle administrator console](server/admin-oracle/README.md)
- [Controlled main-branch operations and verified Oracle downloads](ops/oracle-project/README.md)

## GitHub Environments 与主备 IP 参数

后续换 IP 无需手动 SSH 或重新打包客户端。将主备公网/服务器私网地址填入 `oracle-ops` 的 **Environment variables**，运行 **Primary and backup IP settings** 生成可查看的配置 PR，合并后由既有工作流应用到服务器。OCI 绑定和 DNS 仍需独立核对，保存变量本身不会改动云资源。

| 场景 | 修改哪些参数 |
| --- | --- |
| 准备新主入口 | `PROXY_PRIMARY_IPV4`、`PROXY_PRIMARY_PRIVATE_IPV4` |
| 准备新备用入口 | `PROXY_BACKUP_IPV4`、`PROXY_BACKUP_PRIVATE_IPV4` |
| 本轮主绑定交换完成 | 只将 `PROXY_PRIMARY_PRIVATE_IPV4` 从 `10.0.0.220` 改为 `10.0.0.6`，运行 `cutover` |
| 临时优先使用备用入口 | 可选 `PROXY_ACTIVE_INGRESS=backup`；恢复时设为 `primary` |
| 暂停/恢复 main 自动项目部署 | `ORACLE_PROJECT_AUTODEPLOY`；不会禁用显式手动维护入口 |
| 密码、SSH 或 OAuth 身份轮换 | 对应 Secrets；同实例换 IP 通常不需要改任何密钥 |

完整的三个 Environment 用途、所有当前引用的 Variables/Secrets、每项参数何时修改及工作流临时参数区别，见 **[GitHub Environments 参数说明](docs/github-environments.md)**；地址变更顺序见 [主备目录操作说明](ops/network/README.md)。请保留尚未核实用途的历史环境及现有 Secrets。

Since rc22, both Windows distribution forms bundle .NET 10 LTS; users do not need
a shared .NET installation. A weekly check detects new stable runtime patches
and approaching support expiry; installed clients receive fixes through tested
product releases. Historical .NET 8 lab/preview projects below are not included
in either current product distribution.

The console runs on Oracle behind Caddy HTTPS, with a fixed local administrator
login and an unprivileged Python web service. Administrator-created VPN accounts,
explicit device enrollment, monthly quota/expiry limits, live server counters,
and delayed OCI billing observations have separate roles. Official billing data
is delayed and must not be presented as a real-time free-allowance meter.
Cloudflare provides existing DNS hosting; Zero Trust, D1, Workers and card
binding are not required.

Current Windows/Oracle acceptance verifies actual carriers and dual-stack
Oracle egress, authenticated control, fail-closed faults, owned recovery and
installer lifecycle. Trusted publisher signing and complete earliest/pre-login
packet observation remain separate limits; prior user hardware evidence is
version-specific. See the release's exact successful main workflow and BUILD.json.

The remainder records historical read-only previews and disposable cloud labs.
Those lab binaries and CI administration harnesses must not be redistributed as
the current client or run on a production PC.

## Historical engineering capabilities (cloud labs only)

| Gate | Narrow result | Critical limitation |
| --- | --- | --- |
| G13 | Linux kernel WireGuard across three separate network namespaces; IPv4/IPv6, synthetic DNS and link outage | One cloud VM, not two independent public hosts |
| G14 | Real Windows WireGuardNT app UDP send/receive and synthetic DNS | Two peers on one hosted Windows VM |
| G17 | Windows native IPv6 application UDP and DNS AAAA in tunnel lab | No external IPv6 or Windows DNS leak proof |
| R4 | In-memory authorized intent planner, reject replay and implicit OFF | Not connected to production SCM or WFP |
| R5 | Temporary status-only LocalSystem service install/GUI IPC/uninstall | Not a functional VPN installation |
| R6 | Stop real test WireGuardNT peers, remove adapter and routes, check DNS/firewall baseline | Narrow routes only, no OS fail-closed |
| R7-R8 | Windows WFP-backed scoped filter lifecycle and real IPv4 TCP deny/restore | Not a whole-device kill switch; external IPv6 baseline unavailable |
| R9 | Read-only candidate-port inspection for existing Linux server | No server SSH access or sidecar deployed |

Evidence is linked in docs/source-baseline-status.md.

## Build and safety

Historical manager and preview GUI projects (Windows 11 x64, .NET 8; not shipped in current releases):

- clients/windows/manager/OracleProxy.LabManager.csproj
- clients/windows/app/OracleProxy.Windows.Preview.csproj

The Windows release preview MUST build with
EnableDisposableLabControls=false (default) and must not package
tunnel.dll, wireguard.dll, any private key, test configuration or CI manager
that can start tunnels. See docs/windows-release-criteria.md.

Native WireGuardNT and official WireGuard Windows tunnel sources are used in
CI with upstream pins. Attribution, binary provenance and license obligations
need full review before any distributed product is offered.

**Never run** scripts under clients/windows/lab, lab/wfp-scoped, or
lab/windows-packaging on a production PC. Some scripts deliberately create
real temporary firewall rules and SCM tunnel services, but are hard-gated
to disposable GitHub-hosted runners. Never try to bypass these gates.

## Still blocking functional Alpha and general availability

1. An audited, protected installable native WireGuard engine and authorized
   production GUI-to-SYSTEM control path (the current live control is CI-only).
2. Actual durable fail-closed WFP enforcement for IPv4, IPv6, UDP/TCP, DNS
   and startup/crash/reboot, proven by independent packet captures.
3. Safe OFF, uninstall and emergency rollback under real outages.
4. True two-host cross-network transport, independent recovery console,
   and verified UU remote-control continuity without bypass mistakes.
5. Signed installer/uninstaller, third-party notices, secret lifecycle,
   reproducible release artifacts and final security signoff.

**No production Release should be created or called WireSock-compatible
until these gates are demonstrated.** GitHub Actions green checks verify
only each named, narrowly scoped test.

Project branches are historical engineering evidence. The main branch is
intended to track source code, not an installed VPN. Any future public
release must use reviewed release gates in release/.

No local hypervisor installation or purchase of a new Oracle instance is
required for the cloud tests in this repo. The existing Oracle server,
WireSock and UU remain outside all CI experiments.


### 后台账号：限速、30 天周期与在线统计

用户管理可分别填写共享下载、上传上限（0.1–10000 Mbps），空白不限。
Mbps 为每秒 1,000,000 比特；GB 为 1,000,000,000 字节。
同一账号的全部设备及 IPv4/IPv6 共享对应方向的上限，并非每台设备各获得一个额度。
限速设置、数值和标志仅在管理后台展示；自研客户端不展示限速标志，客户端账号接口不返回限速字段。
限制应用在服务器 `wg0` 的解密后流量，因此原生 UDP、QUIC、HTTPS 中继及 FlClash 使用同一策略；不限制管理站点或 SSH。
内核允许短时突发；协议开销和上传丢包整形会使测速与填写值存在差异。
控制服务遇到外部应用已占用的队列时拒绝覆盖，并停止续期受管放行租约；应检查服务错误后清除相应用户限速恢复。

每位用户自首次分配账号密码的时刻开始，每 **30×24 小时**一个周期，区间为 `[起点, 终点)`。
修改名称、额度、设备限额、密码、启停状态均不会改变原始起点；最终到期日独立于周期，长期账号显示“长期”。
网页显示“本月周期已用”、当前周期区间、账号分配时间和最终到期日。
旧账号优先迁移账号分配审计时间；缺少旧审计时使用已有账号记录时间并标注“旧记录推定”。
初次迁移缺少精确历史明细时保守计入与当前周期重叠的自然月总量，明确标示“保守估计”，不会清零已用量。
后续周期按采样增量独立记录；边界精度受 5 秒采样间隔影响。旧明细缺口不补造零值。
**服务器 OCI 总出站预算仍按 UTC 自然月，与账号 30 天周期分别计算。**

“当前代理连接”显示去重在线用户数、在线设备总数及设备列表。
原生客户端须有近期心跳、已连接状态和近期内核握手；预热/断开设备不算连接。
无客户端心跳的 WireGuard/FlClash 依据最近 180 秒握手估计，离线显示可能延后；采集过期时显示未知。

本地管理员在“管理员账号”提交当前密码、新密码和确认密码即可修改管理站点密码。
新密码至少 12 字符；当前浏览器保留登录，其他浏览器会话失效。
GitHub Environment 的初始管理员密码仅用于首次开通，不再在每次部署覆盖网站修改后的密码。
遗忘密码时需由具备服务器维护权限的管理员显式运行 `provision_local_admin --reset-password` 重设；普通部署不会重设。
账号设备密码和网站管理员密码彼此独立。
