# 用户、Peer 与流量监管

最终产品仍是独立 Windows 便携客户端与可监管服务器的网页后台。管理员网页负责用户策略，
Windows 普通界面负责日常连接；不得把 SSH、WireSock、官方 GUI 或 FlClash 变成日常连接依赖。

## 管理操作

1. 创建用户，填写月配额 GiB、有效期（浏览器本地时间）与启用状态。空配额/有效期为不限/长期，0 配额立即阻断。
2. 从既有 Peer 列表点绑定并选择用户，或填入客户端本机生成的公钥新建 Peer。
   系统只管理独立私有 /32 或 /128 设备地址，拒绝把整段网络路由作为个人设备纳管。
3. 同用户设备共享 UTC 自然月的上传+下载额度。变更归属先计入旧用户；调额、禁用再启用不会清空已用量。
4. 查看设备握手、用量和接入信息。未握手不等于离线；设备统计从采集启用起记录，不伪造之前的历史。
5. 在出站保护中设置额度、安全余量及截至当前时刻核对后的本月已用量，再明确勾选启用全局保护。
   不填新基线时，修改额度/余量保留原基线与增量。填写基线时必须同时确认，视为当前时刻重新校准。

后台只有经过完整 GitHub+MFA 的管理员可以修改。所有写请求保留 CSRF 校验并记录操作审计。
普通 VPN 用户不会获得管理员身份；其公钥对应已绑定的设备和用户策略。

## Oracle 额度的正确解释

官方参考：https://www.oracle.com/cloud/networking/virtual-cloud-network/pricing/
官方用量延迟说明：https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm

官方公开每月首 10 TB 出站免费；Cost Analysis 数据可能延迟最多 48 小时。
本产品配置中的 TB/GB 为十进制字节，用户 GiB 为二进制字节；默认额度是参考值，应核对账号/区域/账期。
当前用户确认未升级为按量付费，只有这一台实例；仍不能把隧道收发字节当作 Oracle 官方账单。

- 用户用量：WireGuard 服务器接收与发送字节的持久增量；多设备合计。
- 本机出站：外部 IPv4/IPv6 路由对应的物理 VNIC 发送字节，接口去重，含 HTTPS、SSH、更新等非 VPN 流量。
- 本账期估算剩余：核对的当前用量基线 + 此后本机出站增量，从管理员设置的额度中扣除。
- VPN 可用预算：估算剩余减去保留余量。保护只阻断 VPN，其他系统流量仍能消耗余量。

首次启动未知的历史不能默认为零。历史未核对、计数缺口或账期无法连续覆盖时余额为未知；
若已开启全局保护，则未知即阻断。连续观测跨入新的 UTC 自然月时才可自动以零开始新账期。
默认采用 UTC 自然月，管理员须先核对与 Oracle 账号周期是否一致。
Oracle 官方 API、历史回填和账期自动核对未接入；手工输入延迟报表时应保守增加未入账流量。
这是一套本机监测与保护机制，不能承诺绝不超出官方额度。

## 执行与故障行为

root-only `/var/lib/oracle-proxy-control/ledger.sqlite3` 保存策略、按月账本和审计。
网页不能读取/修改该文件，只能连接 `/run/oracle-proxy-control/control.sock`。
服务验证 SO_PEERCRED 只接受网页 UID；网页反向验证服务 UID 为 root。
RPC 只有 state、user.put、peer.assign、peer.create、budget.set；无路径/接口/服务名/命令参数。
它只用固定 wg 查询，不读取 wg0.conf、不用 wg dump，不接触私钥或 PSK。

iptables/ip6tables 仅维护 OPX_IN/OPX_FWD 自有链及带 oracle-proxy-control 标记的钩子；
ipset 仅维护 OPXMAN/OPXOK/OPXALL 的 IPv4/IPv6 集合。
既有未纳管 Peer 不受用户配额限制。开启总量保护则包含未纳管 Peer。
规则位于原有 established-accept 前，覆盖已建立连接、UDP 和本机 DNS。
每约 5 秒观测并续租，内核放行租约最多 20 秒，靠近到期时进一步缩短。
控制服务异常时不续租；GUI、网页或控制进程退出不清除已安装规则，内核自行到期阻断。

systemd Type=notify 在防火墙初始化与 socket 就绪后才报告 ready。
wg0 的专用 drop-in 要求开机先启动控制器，并在启动前检查控制器 active。
控制器重启不会连带重启已有 wg0；网页回滚不会停止控制器或清除限制。
SSH/HTTPS 的公网入口不受 wg0 流量规则影响，不使用通配规则放行普通 VPN 流量。

首次部署不纳管现有 Peer、不启动全局保护、不重启 wg0、不改 SSH/路由/端口。
新增 Peer 由控制器自己的持久状态恢复，既有 Peer 的配置和 PSK 保留原管理方式。

## 恢复与客户端整合边界

升级和网页回滚保留 root 账本与策略。备份 root SQLite 时须使用一致性备份 API，
不得以空数据库替代现有账本，否则会失去用量历史；数据库损坏时停止续租并人工恢复。
不能通过停止控制服务解除已纳管设备限制，应由管理员在网页调整策略，或经授权项目运维恢复。

设备信息 schema `oracle-proxy-device-v1` 只含 endpoint、服务器/客户端公钥、地址、DNS 和 IPv6 策略。
Windows 必须在本机生成并保护私钥，通过受保护服务导入已验证配置；后续应加入签名注册与设备身份流程。
当前 JSON 不包含私钥，也不表示 Alpha 已支持最终自动接入。
服务器 IPv6 限制测试不等于 Oracle 具备 IPv6 公网出口，更不替代 Windows 的 IPv6 防泄漏验收。
