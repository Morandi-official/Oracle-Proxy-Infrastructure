# Oracle Proxy 产品进展与交付约定

核查日期：2026-10-20（Asia/Shanghai）。核查基线：`255123f9ae5bc6adbc1bbdb635a28638061e59da`。

## 结论

项目已有可复用的独立 WireGuard 引擎、Windows GUI、LocalSystem 管理服务、安全边界和大量云端实验。
目前尚未达到「可替换 FlClash 的完整 Windows VPN 产品」状态。
GitHub 没有正式 Release。当前可下载的 Windows R114 是未签名实验便携包，
不能以既有云端实验替代生产防泄漏、开机恢复、UU 连续性或端到端公网出口验收。

按用户最新要求，管理后台已改为 Oracle 自托管，不再使用 Cloudflare Zero Trust、D1 或 Workers，
也不要求绑定银行卡。采用 GitHub OAuth/PKCE + 验证器 TOTP、SQLite、普通用户 systemd 服务和 Caddy HTTPS。
域名继续使用 `vpn-admin.morandi.dpdns.org`，Cloudflare 仅承担已有的 DNS 托管。
PR #146 已合并，后台已实际安装到 Oracle，并通过公网 HTTPS 登录页与未登录接口隔离检查。
用户本人的 GitHub 授权、首次绑定验证器与完整登录验收仍待执行；不能以自动化测试代替本人登录。

## 用户已确认

- 主控 Windows 11 x64；受控 Windows 10 x64。
- 需要兼容网易 UU 远程，具备本地可恢复的测试电脑。
- 优先在云端做完所有可自动化测试，实机只做无法由云端证明的最终验收。
- Cloudflare 已托管 `morandi.dpdns.org`，账号使用 GitHub 登录。
- 拟用后台域名 `vpn-admin.morandi.dpdns.org`，管理员邮箱 `morandi@nuaa.edu.cn`。

Cloudflare 账号登录与产品后台登录相互独立；后台改用 GitHub OAuth，默认允许 GitHub 数字账号 ID `204281968`（Morandi-official），
并要求验证器动态码。邮箱不作为授权依据。

## 从源码与日志得到的实际进展

| 模块 | 已存在的实现/证据 | 尚缺的最终条件 |
| --- | --- | --- |
| Windows 便携 GUI | R114 自包含 x64 程序、离线 X25519 密钥生成、集成 tunnel.dll 与签名 WireGuardNT DLL | FlClash 风格完整界面、延迟/流量真实遥测、稳定用户连接流程 |
| 独立 WireGuard | `wg-alpha/EmbeddedWireGuardBridge.cs` 集成官方 MIT 隧道库，日常不依赖官方 GUI | 与产品级认证 IPC、持久保护、密钥存储和升级机制整合 |
| 系统服务 | `manager` 有身份验证、固定动词、LocalSystem 与多个 CI 安全实验 | 默认生产内核仍是 `UnavailableProductionKernel`，不能用开关绕过 |
| 防泄漏 | WFP IPv4/IPv6、TCP/UDP/DNS、崩溃与恢复的多项隔离实验 | 持久/开机保护、多网卡、真实重启、独立抓包及完整状态机整体验收 |
| UU | 有连续性证据门禁 | 网易 UU 在两种 Windows 上的真实长连接、重连和例外策略验收 |
| Oracle | 已部署受限只读 Agent；日志确认 wg0 ACTIVE、接口 PRESENT、UDP51820 LISTENING | 握手、Peer 清单、用量与受限配置执行器，IPv6 公网出口能力核实 |
| 网页后台 | 已部署 Oracle 自托管版本：HTTPS、GitHub OAuth/PKCE、TOTP MFA、SQLite 审计、本机诊断、systemd 注册与回滚 | 本人完整 OAuth/MFA 登录验收；Peer/用量与配置接口 |
| 安装和升级 | 部分生命周期与回滚实验、来源校验 | 发布者签名、受保护服务安装、升级事务、卸载/重启恢复与密钥迁移 |

Oracle 部署实证：[Actions 39415011683](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39415011683)。
日志为 `deploy-agent`，包含 `AGENT_DEPLOY=OK`、上述三项服务诊断和 `PRODUCTION_NETWORK_CHANGED=NO`。
这是 2026-10-20 19:27 左右的历史观测，不代表阅读本文时仍在线。

Windows 最近成功 R114 构建：
[Actions 39218330880](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39218330880)，
源码 `464ad5cd79ccd6c2ff7df8fe98ee075479141120`。
[下载实验便携包](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39218330880/artifacts/12169974965)。
Artifact 名称 `OracleProxy-R114-Offline-Keys-Single-Extraction-UNSIGNED`；
72,167,834 字节；归档元数据 SHA256 为
`e066904b08dfaed56f78f574250a7c2e0957aad6dcf11895bc4bb579d41cf3f9`。
该哈希来自 GitHub 元数据，本次未独立下载全部归档并逐字节复核。
按当前 GitHub 元数据将于 2026-10-26 15:50（中国时间）过期，届时应重新构建，不能当永久下载地址。

## 最终产品架构

```mermaid
flowchart LR
  UI[Windows 普通权限 GUI] -->|身份验证的固定 IPC| S[Windows 系统服务]
  S --> K[受保护 WireGuard 引擎与密钥]
  S --> F[持久 WFP 与 UU 专用例外]
  K -->|加密 UDP 隧道| O[Oracle WireGuard 出口]
  A[管理员浏览器] -->|Caddy HTTPS + GitHub OAuth + TOTP| W[Oracle 非 root 管理后台]
  W --> D[本机 SQLite 状态与审计]
  T[普通用户本机定时采集器] -->|固定只读诊断| O
  T --> D
  G[GitHub CI] -->|构建与云端服务生命周期验证| W
```

Windows GUI 只发送固定动作与配置标识；服务从受保护存储读取配置和密钥，
不接收 GUI 提供的任意命令、脚本、服务名或文件路径。服务端管理面不承载 VPN 数据。
Windows 的 WireGuard Endpoint 直达 Oracle；管理后台 HTTPS 和 VPN UDP 为独立入口。

### 流量与保护约定

1. 日常连接由普通权限 GUI 操作，首次安装服务/驱动和卸载需要 UAC。
   「便携包」是分发形式，不代表系统 VPN 可以完全免安装或免提权。
2. 安全模式下先建立独立于 GUI 生存期的 WFP 防护，再启动隧道；握手和探测成功后显示已连接。
   异常断开保持防护，不能把超时自动解释为允许直连。
3. 显式断开与故障分开：界面需要明确选择「断开且继续阻断」或「关闭保护并恢复直连」。
   服务仅在确认本产品隧道已停止、路由/DNS 已恢复后执行后者。
4. TCP、UDP、IPv4、IPv6 和系统 DNS 均需覆盖，含多网卡、热点、睡眠恢复、DHCP 和网卡变化。
   Oracle IPv6 公网出口未经验证；若不可用，必须阻断 IPv6 防止泄漏，并明确不宣称已支持 IPv6 出口。
5. UU 为明确的直连例外。应根据实际签名程序、子进程及 relay/直连行为制定规则，
   不能通过宽泛 IP 或任意应用直连放行。其直连是声明的产品策略。
6. Windows 私钥在本机生成、由 SYSTEM 受保护存储持有，不上传后台。
   R114 当前是受 ACL 限制的明文测试私钥，不能冒充最终的服务端密钥保护机制。

## 后台当前交付范围

目录 `server/admin-oracle/` 是可以构建和注册为系统服务的 Django 应用，含真实接口和中文界面。
SQLite 替代 D1；本机每分钟定时采集替代 GitHub→Cloudflare 公网 HMAC 上报。
默认不展示模拟在线设备或流量；无报告显示未知，报告超过 180 秒显示过期。
浏览器只读；Peer、逐设备用量和配置修改仍明确未接入。

身份验证使用成熟的 django-allauth：GitHub OAuth 状态校验及 PKCE、数字 UID 白名单、
强制 TOTP，校验完整登录会话中的 GitHub 与 MFA 记录。绑定验证器不等同完成 MFA 登录。
拒绝本地密码认证、注册和密码重置。动态码防重放/限速缓存保存在共享数据库，
TOTP 秘密用独立 Fernet 密钥加密；主机配置仅 root 可读，应用通过 systemd 获取必要环境变量。

部署指南和免费的 GitHub OAuth App 设置见
[Oracle 管理后台 README](../server/admin-oracle/README.md)。
新 CI 覆盖 Python 3.11/3.12，以及一次性 Linux 主机上真实 systemd 的启动、升级、失败恢复、回滚。
它不修改或停止现有 Oracle 的生产 VPN。

用户已明确授权 GitHub 以 root 执行可信 main 中的项目安装、配置、部署、HTTPS、服务管理和回滚。
一次性 bootstrap 已由服务器管理员执行，新增 `oracle-project-ci` 通道已通过真实 SSH 预检。
main 中的运维代码可以改变 root 行为，因此 main 写权限是管理员边界；网页进程仍无 sudo。
原有 `oracle-ci` 保留，交互 shell、SFTP、转发仍禁用。授权与撤销见 [项目运维指南](../ops/oracle-project/README.md)。

实际主机为 Ubuntu 22.04.5 ARM64。后台独立使用校验和固定的 Python 3.12.15，
Caddy 2.11.7 负责 HTTPS，未替换 Ubuntu 系统 Python。
HTTPS 安装保留原有 Caddy host，增加专用配置与带标记的 TCP 80/443 放行规则，
通过专用 systemd oneshot 服务开机恢复；未改动 SSH、WireGuard Peer 或路由。
真实状态检查确认后台本机健康、Caddy active、原 wg-quick@wg0 active。

Peer/端口写入仍需要后续 Oracle 固定权限执行器，建议事务：
创建带版本的请求 → 预检与白名单校验 → 生成只属于本产品的配置 → 保存已知正常版本 →
应用 → 独立连通性检查 → 超时回滚 → 审计结果。

## 云端优先的验收顺序

| 顺序 | 云端可完成 | 必须补充的外部证据 |
| --- | --- | --- |
| 1 | Windows 编译、离线密钥向量与 ACL、IPC 越权、固定命令边界、包内凭据扫描 | 发布者代码签名身份 |
| 2 | 隔离 Windows 的真实 WireGuard/WFP、UDP/TCP/DNS、服务崩溃恢复与精确清理 | 启动前防护与真实系统重启，不能用进程重启替代 |
| 3 | Oracle 受限诊断、独立 Peer 的跨公网握手和出口探测、管理后台身份/审计/回滚 | 授权的测试 Peer 与可回滚服务器配置；先核实 IPv6 能力 |
| 4 | Oracle 后台 OAuth/MFA 错误矩阵、SQLite、真实 Linux systemd 生命周期/回滚 | 实际 OAuth App、Oracle 安装、DNS 与 HTTPS 登录验收 |
| 5 | 已有实验不能证明真实用户侧的 ISP/NAT/UU 行为 | Win11/Win10 本地可恢复电脑上的网易 UU、长连接、断网/重启验收 |

完整上线前还需验证签名安装/升级/卸载中断、密钥迁移失败、配置错误和版本回滚。
最终 Windows 构建应生成自己的版本号、校验和、依赖许可证、构建来源和可供复核的测试报告。

## 当前验证与阻塞

Oracle 自托管版的 16 项 Django 集成/身份测试、4 项部署边界测试在本地通过，
包含模拟 GitHub API 的完整 OAuth → 首次绑定 → 重新登录 → 动态码验证流程；
拒绝错误账户、伪造 state、仅链接账户、绕过 MFA、错误/重复动态码、本地密码和过期会话。
Django 部署安全检查与静态资源构建通过。云端检查以 PR #146 最新提交的 Actions 为准，
不把旧版 Cloudflare 检查结果算作 Oracle 部署证明。

用户已完成 DNS、GitHub OAuth App、GitHub Environment Secret/Variable 和一次性 root 通道授权。
真实 SSH 运维和后台部署已执行，DNS 正确指向 Oracle，公网证书可信。
未登录的状态/审计接口返回 401，公网健康路由返回 404；本地密码设置、重置及注册关闭。
最终部署与公网检查日志见 [Actions 39435712224](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39435712224)。
仍需用户本人完成首次 GitHub 授权与验证器绑定，核实完整浏览器登录。
Client Secret、MFA 加密密钥与 SSH 私钥不应发送到聊天、代码仓库或 CI 日志。
后台上线后仍需继续 Windows 产品整合、防泄漏与 UU 验收，不把只读后台或 R114 实验包标为最终成品。
