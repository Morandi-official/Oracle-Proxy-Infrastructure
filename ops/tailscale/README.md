# Proxy Tailscale 迁移

Tailscale 系列的首个 Windows 和 Android 对外版本号为 `0.1.0`。发布标签使用 `tailscale-windows-v0.1.0` 和 `tailscale-android-v0.1.0`，避免与旧系列标签冲突。Android 覆盖安装继续使用原有应用 ID 和签名，内部 `versionCode` 递增。

## 云端隔离实验

[Tailscale migration data-path lab](../../.github/workflows/tailscale-migration-lab.yml) 在一次性 Linux 运行机中使用独立的 Headscale 数据库。客户端、出口和测试目标运行在不同的网络命名空间中。控制面与外部测试目标均无需生产账号、密钥或 DNS 配置。

- 已授权设备使用一次性、有时效的注册链接身份加入，重复使用同一密钥无法登记另一台设备。
- 只有授权设备通过 Tailscale 串联的 WireGuard UDP 直连，访问独立 IPv4 和 IPv6 出口测试站点及 UDP DNS 服务。
- 未授权设备和已撤销设备无法使用同一个出口。
- Linux 出口读取已登记节点自身的传输计数。如果授权刷新中断，IPv4 和 IPv6 转发权随内核租约到期，最长 15 秒。
- Windows 验证签名的 Tailscale 引擎可以在专用受保护管道上启动，并由 .NET 客户端读取状态。Android 构建适用于 ARM64 手机及 x86-64 模拟器的原生接口。

## 接入生产前的兼容性

Oracle Linux 作为出口节点。后台继续管理 Proxy 账号、设备与配额。正式客户端登记必须对应独立的 Tailscale 节点，后台需要同步停用、到期、流量额度和设备撤销，并保留服务器侧的使用量统计。Windows 的系统路由和断线保护，以及 Android 的系统 VPN 权限与恢复流程，需要在两端分别通过真实设备测试。

隔离实验仅设置 WireGuard UDP 直连。中继是否启用和相应出口策略需在生产改造中单独验证。第一阶段工作流仅运行验收。
