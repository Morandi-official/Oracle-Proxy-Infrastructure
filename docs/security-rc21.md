# rc21 轻量安全审查

审查日期：2026-10-27。以下区分仓库配置、已测试的边界和仍待验证的部署状态；它不是渗透测试报告，也不保证不存在未知漏洞。

## 已有防御与本轮补强

此表描述仓库中的设计、配置模板和测试；未在本次审计中逐项读取生产进程的有效 systemd/内核策略，因此不等于所有在线实例均已核验。生产生效状态应由后续只读观察确认。

| 层级 | 仓库中的控制与验证 |
| --- | --- |
| 管理网站 | Caddy HTTPS；Gunicorn 只监听回环；Django 禁用 DEBUG、固定 Host、CSRF、HSTS、CSP、禁止嵌入页面及媒体权限。固定管理员账号，不开放注册；登录全局与用户级限流；Secure/HttpOnly 的 host-only cookie，固定 30 天到期，退出或改密码可使会话失效。 |
| 普通客户端 API | 独立账号体系，随机 Bearer，仅存令牌摘要；拒绝 Cookie/Origin 的浏览器认证混用；确认设备后才登记，配额/到期/撤销由服务器实施。HTTPS/QUIC relay 有认证、帧长、并发、速率和超时边界，只转发至固定本机 WireGuard 端点。 |
| 主机与权限 | Web、HTTPS relay、QUIC relay 分别使用非 root 账号；systemd 配置只读系统目录、禁止提权、资源上限及地址族限制。Web/采集器阻断实例元数据地址；需要实例身份的官方用量探测进程独立运行，仅使用现有只读 IAM。 |
| 根控制器 | 通过受限 Unix socket 和对端 UID 接受固定操作，字段、地址、名额、预算及持久化均在控制器再次验证，不提供 shell。新增完整 system actor 操作白名单：health 只能读 state，client-api 只能读 state 或执行已确认 peer.enroll；管理变更在计费 tick/副作用之前拒绝。正常登记复用原有私有 peer 创建逻辑，不伪造管理员身份。 |
| 安装版 | 与便携版使用同一套受保护服务；安装版新增固定桌面目录的受保护 DACL、可信 owner 和 marker 检查，拒绝采用其他程序或普通用户可写目录。安全断开失败时阻止标准卸载继续删除文件。最终是否通过必须以精确构建的 Windows 安装/升级/卸载验收为准。 |
| 发布与依赖 | 仅提升通过 main 验收且有精确摘要的构建；Oracle 镜像按大小/SHA-256 验证。新增每周依赖更新配置，每个生态最多一个普通待处理 PR，不自动合并。此配置不代表仓库的安全告警或自动安全更新开关已启用。 |

控制器回归覆盖：system actor 的管理操作拒绝且不触发 tick；原生登记仍可创建、幂等复用，拒绝未确认或已撤销设备；现有配额、预算、所有权和 IPv6 用例继续通过。它防止内部角色误路由扩大权限；不能声称一个已完全攻陷的 Web 进程无法伪造管理员 actor。完整 Web 进程失陷仍可能危及其业务权限，但固定 RPC 继续限制 OS 命令面。

## 反编译与性能边界

项目与集成核心已有 GPL 许可及对应源码交付义务，仓库也公开。不能把隐藏代码或隐藏接口当作认证机制，不能把服务器私钥、管理员口令或可复用的全局秘密放进安装程序。用户已有的客户端本机密钥/令牌继续由 SYSTEM 服务和 DPAPI 保护，普通界面不接收密钥。

便携版不新增反编译处理；安装版不引入反调试驱动、虚拟化重壳、运行期字符串解密或自签根证书。现有 Release 构建去除调试信息/符号，安装包压缩仅用于交付体积，不宣称能阻止反编译。额外混淆如需采用，必须保留许可证与相应源码、验证精确变化后的载荷，并评估升级/杀毒误报和运行开销。当前未配置可信 Authenticode 发布者，不能承诺没有 SmartScreen 或未知发布者提示。

## Oracle 能承担的部分

Oracle 官方说明，所有 OCI 账号已包含网络层 L3/L4 DDoS 防护，无需另行配置。这减少基础设施防护的自建工作；VCN 安全列表、NSG 和 IAM 仍需要正确配置。它不保护应用口令、CSRF、账号权限、SQL、依赖漏洞或业务层请求滥用，这些仍是项目责任。

Cloud Guard 提供云资源配置/活动检测，但官方启用文档明确免费租户无法完成启用。此用户未升级按量付费，因此本轮不以它作为现有防御前提，不要求绑卡。Security Zones 和额外 WAF/Network Firewall 也不是本项目当前已验证的默认防护；盲目启用可能限制公网资源或引入费用/额外路径。本轮不创建收费资源，不改动会切断 GitHub 运维通道的 SSH/云网络规则。

官方资料核对：

- [OCI Security Overview：共享责任与内置 L3/L4 DDoS](https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_overview.htm)
- [Cloud Guard 启用及免费租户限制](https://docs.oracle.com/en-us/iaas/Content/cloud-guard/using/part-start.htm)
- [Oracle 价目表：Security Zones、WAF 等独立服务](https://www.oracle.com/cloud/price-list/)

## 尚未证实或后续事项

- 本次代码审查没有读取 OCI 网络/IAM 的完整实时配置，也未证明 Cloud Guard/WAF 已启用；现有实例身份权限限于用量/监控。
- 线上可按固定白名单只读核对：本产品 unit 的实际用户、capability、只读路径与 IMDS 阻断策略；Ubuntu unattended-upgrades 更新状态、AppArmor 实际加载状态、sshd 选定的口令登录/root 登录/转发配置。不要输出整份环境、全部 sshd 配置、授权密钥或私钥，也不要在未核对运维路径前自动更改 SSH。
- 客户端真实重启后恢复和双栈出口已在 rc20 观察到；最早开机至登录前的全程流量证明，以及 rc21 当前字节的实机回归，不能由源码检查替代。
- 已认证状态接口仍需持续评估资源耗尽风险；本轮没有为了限流而改变正常客户端/relay 的刷新时序。服务资源上限和 relay 限制已经存在。
- 当前 Windows 自包含包使用 .NET 8 LTS。微软公布的支持结束日期为 2026-11-10，距本次审查很近，应安排升级到仍受支持的 LTS 并重做 Windows 10/11、安装、WFP、单文件加载及恢复验收；本轮不仓促替换运行时。官方生命周期：[.NET 支持策略](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core)。
- 固定版本依赖不等于永久无漏洞；更新 PR 仍需代码审查与完整 CI。GitHub Actions 当前使用版本标签，进一步固定官方 action 的完整提交 SHA 属于后续供应链加固。
- GitHub current-main root 运维桥是用户明确授权的信任边界：能修改 main 的身份能更新项目 root 运维代码。它保留强制命令、固定仓库/操作、禁止转发和已固定 SSH 主机身份，不能描述为隔绝恶意 main 代码的 OS 沙箱。
