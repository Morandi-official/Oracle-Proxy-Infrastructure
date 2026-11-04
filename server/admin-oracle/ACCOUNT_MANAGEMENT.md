# Administrator account lifecycle and official usage

Only the configured GitHub administrator with recent OAuth and MFA can use `/api/control`. Native client credentials never grant dashboard access. The single user form saves display name, client username/password, quota, expiry, enabled state and device limit (default 3). A blank password during editing preserves the hash. Password/username changes invalidate bearer sessions; disabling the user or revoking a device stops tunnel traffic.

Deletion tombstones the root policy and revokes every attached public key before removing credentials/sessions. Users disappear from the active list; accounting, addresses and audit history remain. Revoked public keys cannot enroll again, including after controller restart. Recreate a user with a new identity and new device keys. Changes across the web credential database and root policy ledger stage access disabled; a partial failure leaves a disabled row that the administrator can edit and retry. Saving does not reset usage.

The independent `oracle-proxy-oci-usage.timer` queries official APIs every 15 minutes. It uses short-lived instance-principal authentication; no API private key is requested, saved in GitHub or exposed to the web application. The probe is bounded separately from the 5-second kernel lease loop. Its root-only cache contains structured observations and non-secret resource identifiers for IAM setup. Raw exceptions, IMDS certificates and tokens are never logged. Web/collector systemd units deny access to the IMDS credential endpoint.

Monitoring queries `oci_vcn.VnicToNetworkBytes[1h].sum()` for attached VNICs, from UTC month start through completed hours. VNIC metrics include internal traffic and traffic before drops. They are not a billable internet-egress balance. Usage API rows retain SKU and units for review; absent rows and pagination never imply zero usage. Unverified coverage and billing delays leave the remaining allowance unknown; the probe does not silently overwrite a manually confirmed baseline or enable budget enforcement.

When instance-principal authentication is available but API access is denied, create an Oracle dynamic group matching **only this instance**. The administrator dashboard shows the resource identifier. Grant only `read metrics` in the subnet's compartment, conditioned on `target.metrics.namespace='oci_vcn'`. Cost Analysis additionally needs tenancy-level `read usage-report`. Do not grant tenancy management or account write permissions. Changes to IAM must be performed by the tenancy owner; server root is not equivalent to Oracle IAM authority.

References:
- https://docs.oracle.com/en-us/iaas/Content/Network/Reference/vnicmetrics.htm
- https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm
- https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm


## FlClash UDP 配置

管理后台“FlClash · 仅 UDP”选择用户、填写一台设备名称并确认归属后创建。每份配置有独立 WireGuard 密钥，计入原设备上限和用户共享流量配额。用“复制链接”交给对应用户，在 FlClash 添加链接；或下载 `Proxy-UDP.yaml` 后导入文件。生成内容是 Mihomo 接受的 JSON/YAML 格式，仅一个 WireGuard UDP 443 节点与 MATCH 规则，没有 DIRECT、QUIC、HTTPS 备用；UDP 失败时停止连通。普通网页的 TCP 会封装在 WireGuard UDP 隧道中，仍可使用。

链接和文件都是接入凭据，不能公开、写入工单或共用；每台设备单独创建。私钥和链接材料在数据库加密，列表与审计不返回密钥；SECRET_KEY 轮换后需重新签发。撤销会立即停止该设备，已下载配置同样失效，历史用量保留。创建中断的“待核查”项不会下发配置，可撤销后重建。账号禁用、到期、超额和总量保护沿用服务端策略。

FlClash 应启用 TUN（配置包含请求），DNS 按规则走该节点。操作系统 TUN 权限、规则覆盖、保护开关由 FlClash 控制，不继承本软件 WFP 防泄漏或 UU 直连例外；仅开系统 HTTP 代理不能覆盖所有应用。复制或修改配置、关闭 FlClash/TUN 都可能改变流量路径。此出口只提供 UDP，不承诺第三方客户端故障时的系统级断网保护。


### 原版 FlClash 名额与运行监控

FlClash 页面只选用户并生成配置，不再要求填写设备名或单独确认。生成前读取最新策略并核对账号可用、设备剩余名额与服务器预算，根策略进程再次原子检查名额。自研设备与 FlClash 独立密钥共用设备上限：上限 3、已有 2 台时只可再生成 1 份。生成即预留名额；重复下载或复制已有链接不新增名额。达到上限后可下载已有有效配置，不能生成新配置；先删除或撤销旧设备才能释放名额。

未知物理身份按“账号的第 N 个 FlClash 设备”命名，列在该用户设备组；首次 WireGuard 握手后保留 FlClash 已使用标记。原版 FlClash 不上报可信硬件身份，同一配置复制到多台电脑仍是一个密钥，无法可靠按物理设备限台或与自研设备自动去重。不能用源 IP、UA 或握手漂移冒充设备识别。该边界同时显示于页面说明。

总览内每 10 秒读取一次主机 CPU、负载、可用内存、根磁盘空间和 inode、物理网卡收发速率/包速率/错误/丢包，以及可读取的 TCP 重传和连接跟踪容量。页面每 5 秒刷新；曲线约 15 分钟，采样保留 6 小时。只计物理网卡避免重复统计隧道流量。重启、计数回退或首轮采样显示未知，不伪造零值。超过 30 秒未采样明确标为过期。阈值变更写入审计，不自动封禁或据此认定攻击。

账单按 UTC 自然月查询（北京时间每月 1 日 08:00 起），不是注册后滚动 30 天。页面分开标注账期起点、查询上限和已用量。查询上限不代表该时刻之前已经完整入账。官方 Usage API 是租户计费条目，本机仅是当前服务器物理网卡采样增量，不能直接视为同口径实时余额。
