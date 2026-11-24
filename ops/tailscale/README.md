# Proxy Tailscale 迁移

Tailscale 系列的首个 Windows 和 Android 对外版本号为 `0.1.0`。两端通过同一次生产验收后发布到 `tailscale-v0.1.0`，包含 Windows x64 安装版、便携版和已签名 Android APK。Android 覆盖安装继续使用原有应用 ID 和签名，内部 `versionCode` 递增。

后续采用 [SemVer 2.0.0](https://semver.org/lang/zh-CN/)。正式版本使用 `MAJOR.MINOR.PATCH`。提高主版本表示不兼容变更，提高次版本表示向后兼容的新功能，提高修订版本表示向后兼容的修复。候选版追加 `-rc.1` 等预发布标识。

## 云端隔离实验

[Tailscale migration data-path lab](../../.github/workflows/tailscale-migration-lab.yml) 在一次性 Linux 运行机中使用独立的 Headscale 数据库。客户端、出口和测试目标运行在不同的网络命名空间中。控制面与外部测试目标均无需生产账号、密钥或 DNS 配置。

- 已授权设备使用一次性、有时效的注册链接身份加入，重复使用同一密钥无法登记另一台设备。
- 只有授权设备通过 Tailscale 串联的 WireGuard UDP 直连，访问独立 IPv4 和 IPv6 出口测试站点及 UDP DNS 服务。
- 未授权设备和已撤销设备无法使用同一个出口。
- Proxy 设备与协调节点的对应关系跨进程持久化，拒绝跨账号读取和重复发放，撤销后先在本地状态标记失效。
- Linux 出口读取已登记节点自身的传输计数。如果授权刷新中断，IPv4 和 IPv6 转发权随内核租约到期，最长 15 秒。
- Windows 验证签名的 Tailscale 引擎可以在专用受保护管道上启动，并由 .NET 客户端读取状态。Android 构建适用于 ARM64 手机及 x86-64 模拟器的原生接口。

## Oracle 接入与正式发布

Oracle 实例作为出口节点。Headscale 接在现有管理域名的 HTTPS 后面。新客户端沿用 Proxy 账号，每台设备对应独立的 Tailscale 节点，服务端沿用用户账本、到期时间和配额，并以短期内核许可限制出口。测试账号的设备在验收后通过本设备会话释放。

新客户端使用独立的 Tailscale 运行时和本地身份存储。Windows 由专用引擎实例负责 VPN 网卡。Android 由系统 VPN 服务接入原生引擎。新客户端使用新的登记流程，直接接收当期出口和账号权限。切换前保留现有服务与账本供生产用户使用。

[正式发布工作流](../../.github/workflows/tailscale-clients-release.yml) 等待 Oracle 协调及账号入口就绪，再使用最终 Windows 和 Android 包实测出口、吞吐、延迟、连接耗时及重连。验收分别记录实际的 UDP 直连或加密中继路径。隔离网络的性能报告单独保留。
