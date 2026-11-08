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
