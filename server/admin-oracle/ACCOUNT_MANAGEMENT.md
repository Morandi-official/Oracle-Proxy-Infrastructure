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
