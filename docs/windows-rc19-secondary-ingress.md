# rc19：第二公网入口

同一校园网、同一浏览器，以原管理域名验证证书，新公网 IP 上的页面、CSS、JS 均为 h3；旧公网入口的强制 QUIC 请求失败。这个对照定位了入口路径差异，并不能单独证明 VPN 隧道可用。rc19 随后使用真实 Windows + Oracle 做了独立隧道验收。

| 通道 | 实际入口 | 用途 |
| --- | --- | --- |
| 原生 WireGuard / UDP | 141.147.78.44:8443 | 默认主通道；保留原生 51820 / 443 兼容路径 |
| QUIC / HTTP/3 | 141.147.78.44:8443 | 用户可选、UDP 主通道的自动备用 |
| HTTPS / TLS | 152.67.156.100:443 | 自动兜底，不增加普通协议选项 |

**已验证出口仍为 152.67.156.100。** 新地址是同一实例的入口，不增加一台服务器、不改变 WireGuard 密钥、账号、设备身份、配额或管理网站 DNS。

客户端从经过身份验证的账号状态获取 `transport_address`；C# 和 Go 分别限制为项目两个固定 IP。旧地址的失败缓存与新入口隔离，缺失元数据时保留旧版兼容行为。HTTPS 始终保留原入口。原生 IPv4 MTU 1200、安全阻断 IPv6 的策略保持不变。

服务器通过 `oracle-proxy-secondary-endpoint.service` 维护指定的第二私网地址；新入口 QUIC 的回复经过单独拥有的规则返回，避免错误使用主公网源地址。现有的 WireGuard 报文分流规则先于 QUIC 规则。服务不修改主地址、默认路由或 DHCP；旧测试租期令牌已失效，持久入口不再按 24 小时到期回收。

## 已完成验收

[Windows 全套真实 Oracle 验收](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/40267581123)，源码提交 `c0908e3c5ac9c7874158f96acdcdf030946170c4`：

- 阻断旧 IP 的三个 UDP 端口时，新入口原生 UDP 8443 和 QUIC 仍可收发、访问网站和解析 DNS。
- 原生 UDP 在低 MTU 下持续 120 秒，同一核心进程保持连接，无消息过大错误或协议回退。
- UDP 冷连接 1895 ms，首次 QUIC 冷连接 2056 ms，预热重连低于 1 秒。这些是云端测量，不能保证所有实际网络达到同样耗时。
- 核心和系统服务故障恢复、防泄漏、QUIC 优先于 HTTPS 的回退、HTTPS 兜底恢复、后台管理网站访问、用量和设备身份联动通过。
- 新入口系统服务的停止/启动、仅移除自有 NAT/地址/元数据的回滚，以及旧租期回调不会移除持久入口，均经过真实 Linux namespace/systemd 验收。

## 升级与回滚

旧版先断开退出，完整解压新包，运行 `OracleProxy.exe`，点击“安装 / 升级服务”完成 UAC。选择 WireGuard / UDP 后连接；成功时诊断应显示 `transport_address: 141.147.78.44`、`transport: wireguard-udp`、端口 8443。现有已登记设备沿用原身份。

服务器回滚由已授权的 GitOps 运维入口完成：将 `ops/oracle-project/request.json` 更新为 `{"operation":"enable-https","request_id":"secondary-vpn-rollback-20261026"}` 并按项目运维流程合入 main。它关闭新入口公告并移除自有规则/地址，保留主入口与默认网络；不要套用全局网络重置。未确认的规则或地址不会被自动删除。

本版本仍为未签名验收候选版。真实用户网络的新版 VPN 路径需要实机确认；IPv6 转发和发布者签名等正式版门槛尚未完成。
