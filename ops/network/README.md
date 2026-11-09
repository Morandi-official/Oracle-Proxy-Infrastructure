# 主备公网地址配置

`endpoints.json` 是原生客户端、FlClash 导出、UDP 六入口诊断、服务器地址管理及 GitHub SSH 部署的共同地址目录。它只含公开地址与内部映射，不含凭据。客户端 rc34 及以后登录、刷新时读取经过 HTTPS 认证的目录，无需为以后换 IP 重新发布客户端。

当前为迁移准备阶段：新主入口 `152.67.154.225 → 10.0.0.220`，备用 `150.230.113.158 → 10.0.0.246`；原主地址仍提供默认出口，保留原有两个入口用于恢复。`egress_ipv4` 暂时同时接受旧、新主出口，完成 OCI 绑定切换后必须缩为新主地址。

## 更换地址的顺序

1. 在 OCI 预留新公网 IPv4，绑定同 VNIC 的辅助私网地址。保留当前入口和 Reserved IP，记录精确 OCID 与绑定，先验证新入口。
2. 修改 primary/backup 地址对，revision 加一；将当前仍需保留的入口放入 legacy（最多两项）。`active` 表示优先入口，备用故障切换不改变公网出口配置。正常情况下 active 为 primary。
3. GitHub 主分支应用 root-owned `/etc/oracle-proxy-quic/endpoints.json` 与对应服务器地址。只改此目录触发轻量 preflight，不重新打包 Windows。服务 `proxy-endpoint-addresses.service` 在重启后恢复所管理的辅助地址，不修改默认路由、策略路由或 IPv6。
4. 客户端正常登录、连接验证新入口；需要使新地址成为默认公网出口时，在 OCI 维护窗口将它绑定主私网 `10.0.0.6`，将原 Reserved 公网暂存到被腾出的辅助私网。先解除被占用的两项，再逐项绑定并读回，禁止 DeletePublicIp 代替解除绑定。
5. 立即更新目录中的 private_ipv4 映射及 egress_ipv4，仅允许实际预期出口；对正常连接与 IPv4/IPv6 做一次验收。同步更新管理域名 DNS 的 A 记录，原记录保存以便恢复。
6. 确认所有在用客户端支持目录、管理访问与部署链路可用后，删除淘汰公网 IP、无用辅助私网 IP、legacy 条目和对应临时诊断资源。保留主私网、IPv6、生产安全规则；按精确资源清单删除。

`active` 切换到 backup 可将备用设为优先入口，但不能自动修改 OCI 公网绑定或 DNS。公网 IP 删除后不能保证找回。

## 兼容与边界

老客户端迁移期间保留旧 API tunnel 字段；rc34 使用 network_endpoints 覆盖实际物理入口与出口校验。WireGuard 配置内旧 `152.67.156.100:51820` 为被自有 transport detour 接管的逻辑 peer 标识，外层报文实际发往目录地址，不代表仍依赖旧公网 IP。HTTPS 始终验证固定管理域名证书。

部署 SSH 以已有 pinned HostKeyAlias 识别同一服务器，按目录主备及 legacy 做只读探测；选定入口后仅执行一次变更操作，不在不确定结果下重放。客户端优先采用已认证目录缓存，两个地址都无法 TCP 连接时才通过物理网卡 DNS 解析管理域名；DNS 结果仍须通过 HTTPS 证书验证。

## GitHub Environment：日后不需要手动 SSH

打开仓库 **Settings → Environments → oracle-ops → Environment variables**，添加以下普通变量（不是 Secrets）：

| 变量 | 当前准备阶段的值 |
| --- | --- |
| `PROXY_PRIMARY_IPV4` | `152.67.154.225` |
| `PROXY_PRIMARY_PRIVATE_IPV4` | `10.0.0.220` |
| `PROXY_BACKUP_IPV4` | `150.230.113.158` |
| `PROXY_BACKUP_PRIVATE_IPV4` | `10.0.0.246` |
| `PROXY_ACTIVE_INGRESS`（可选） | `primary` |

已有 SSH 凭据继续保存在该 Environment，不需要重新录入或发送密码、密钥。普通变量本身不会改变生产；只有运行工作流、查看提案并合并，才会应用服务器配置。

1. **Actions → Primary and backup IP settings → Run workflow**，分支选 `main`。
2. `inspect` 只读取仓库配置和公共 DNS，不访问 OCI 凭据、不改变服务器。输出中的配置是仓库期望值，不是 OCI 实时绑定证据。
3. `prepare`：先在 OCI 网页确认新公网 IP 已绑定辅助私网地址，填写对应变量，选择此模式并勾选绑定确认。旧地址自动保留到 legacy（最多两项，超出会停止，不会擅自删除）。
4. `cutover`：在 OCI 网页完成新主公网 IP 与原主公网 IP 的私网绑定交换并逐项读回后，将 `PROXY_PRIMARY_PRIVATE_IPV4` 改为 `10.0.0.6`，选择此模式并勾选确认。工具仅允许已记录地址之间的绑定排列，并将预期出口收紧为新主 IP。
5. 查看工作流 Summary 中的 PR 链接，核对公网/私网映射、出口和 legacy，再合并。合并触发轻量服务器配置应用；客户端无需重新打包，主备 SSH 维护入口也读取相同目录。
6. 若仓库禁止 Actions 创建 PR，工作流会保留配置分支并给出比较页面链接。由仓库所有者在该页面创建 PR 即可，不需要新建访问令牌。工作流不会自动合并，也不会直接推送 main。

GitHub 使用 `GITHUB_TOKEN` 创建的 PR 不会自动再次触发 PR 工作流，因此生成任务先执行格式与变更规则检查；所有者合并后，main 的精确配置检查和部署仍会运行。只有两份 JSON 的变化才走轻量路径，代码或工作流改变仍走原有检查。

OCI 公网 IP 的创建/绑定/删除、DNS 记录仍是独立的控制面操作。这个工作流不会自动执行这些操作，更不会因为删除变量而释放公网 IP。GitHub 生成提案前需要操作者确认实际 OCI 绑定，避免把期望值误当成已经完成的配置。

迁移完成并确认旧地址已释放后，再删除 legacy 条目和对应辅助地址；不可在交换前删除保留公网 IP。SSH 中旧地址形式的 HostKeyAlias 是同一服务器的公钥身份名称，不是网络连接目标，应该保留。
