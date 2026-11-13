# GitHub Environments、参数与修改时机

本文列出当前 `.github/workflows` 源码实际引用的 Environment、Variables 和 Secrets；不包含或展示任何真实密钥值。GitHub 页面上若还有未被当前源码引用的历史环境，先保留，核对其工作流和保护规则后再决定是否删除。不要仅凭名字批量清理。

## 从哪里进入

仓库 **Settings → Environments → 对应环境**。普通参数填 **Environment variables → Add environment variable**；凭据填 **Environment secrets → Add environment secret**。Environment 自身的 Required reviewers、Deployment branches 是审批/分支保护设置，不是地址参数，不随换 IP 修改。

## 当前使用的三个环境

| Environment | 用途 | 何时需要改 |
| --- | --- | --- |
| `oracle-ops` | 已授权的服务器部署/维护、地址提案、云端诊断 | 换入口 IP 改 `PROXY_*` 普通变量；管理员密码或 SSH 身份轮换才改对应 Secret |
| `windows-client-acceptance` | main 分支的真实 Windows 客户端联网验收 | 仅验收账号变更、密码轮换或账号停用时更新验收凭据；换 IP 不需要改 |
| `windows-product-build` | PR/非生产构建上下文，离线编译和打包 | 不需要生产服务器或真实用户凭据；不要把管理密码复制进去 |

环境名称不能随意改名：工作流按名称选择环境，改名需同时修改源码引用。环境变量不是立即执行的命令；保存变量不会自动切换服务器，需运行相应工作流并查看结果。

## oracle-ops：普通变量（Variables）

| 名称 | 含义/当前阶段示例 | 修改时机与结果 |
| --- | --- | --- |
| `ORACLE_PROJECT_AUTODEPLOY` | `true`：符合路径条件的 main 提交自动执行项目操作；其他值暂停该自动执行入口 | 计划暂停/恢复自动部署时才改。手动 workflow_dispatch 仍是显式执行入口，此变量不是一切维护操作的总开关 |
| `PROXY_PRIMARY_IPV4` | 首选公网入口；当前 `152.67.154.225` | 新主公网 IP 已在 OCI 分配并绑定后改；不会因为填写它而创建或绑定 OCI 资源 |
| `PROXY_PRIMARY_PRIVATE_IPV4` | 上述公网 IP 在 VNIC 上实际绑定的服务器私网 IP；当前 `10.0.0.6` | OCI 实际绑定改变后再同步；历史准备阶段曾使用 `10.0.0.220`。这不是客户端的 WireGuard 内网地址 |
| `PROXY_BACKUP_IPV4` | 应急备用公网入口；当前 `150.230.113.158` | 更换备用公网 IP，且 OCI 实际绑定已确认后改 |
| `PROXY_BACKUP_PRIVATE_IPV4` | 备用入口实际绑定的 VNIC 私网地址；当前 `10.0.0.246` | 备用私网绑定改变时改；主入口交换到 10.0.0.6 时通常保持不变 |
| `PROXY_ACTIVE_INGRESS`（可选） | `primary` 或 `backup`；未填默认 `primary` | 全局目录优先项；账号权限与首选入口仍由后台用户设置决定。它不修改 OCI 绑定或系统默认路由，IPv4 出口跟随实际入口 |
| `ORACLE_ADMIN_GITHUB_CLIENT_ID`（旧 OAuth 模式可选） | GitHub OAuth 应用的公开 Client ID | 仅替换旧 OAuth 应用时改；当前本地管理员登录模式不需要为换 IP 修改它 |

`PROXY_*` 由 **Primary and backup IP settings** 工作流读取。真正的、带版本的服务端地址目录是 `ops/network/endpoints.json`，提案 PR 会写入该文件。只保存 Variables 而不运行/合并提案，不会改变该目录或运行中的服务。

## oracle-ops：凭据（Secrets）

| 名称 | 含义 | 何时才修改 |
| --- | --- | --- |
| `ORACLE_CI_OPS_KEY` | 自动维护使用的受限 SSH 私钥，由工作流代替人手连接服务器 | SSH 密钥轮换、实例重建、原授权失效时。换同一实例的公网 IP 不需要更换密钥 |
| `ORACLE_CI_KNOWN_HOSTS` | 服务器 SSH 主机公钥的固定信任记录 | 服务器主机密钥经过可信渠道确认发生变更时。当前工作流保留 `152.67.156.100` 形式的 HostKeyAlias 作为原有公钥身份名称；它不是实际连接目标，释放旧 IP 后也不应盲目改掉此身份记录 |
| `ORACLE_ADMIN_LOCAL_USERNAME` | Web 管理后台的本地管理员用户名 | 管理员身份变更时，与下面密码成对设置；不是普通 VPN 客户端账号 |
| `ORACLE_ADMIN_LOCAL_PASSWORD` | Web 管理后台的本地管理员密码 | 计划轮换后台密码时改。运行 configure/deploy 后才会同步，服务器保存密码哈希；不要贴到聊天或源码 |
| `ORACLE_ADMIN_GITHUB_CLIENT_SECRET`（旧模式） | 旧 GitHub OAuth 应用密钥 | 旧 OAuth 模式下轮换应用时才改；当前工作流优先使用已同时设置的本地管理员用户名/密码，不应为换 IP 随意删除它们或切换登录模式 |

SSH 维护工作流共享地址目录，先做只读探测，再对选定入口执行一次变更操作，不在结果不确定时换地址重放变更。服务器公网变了不等于主机公钥变了。

## windows-client-acceptance：凭据（Secrets）

| 名称 | 含义 | 修改时机 |
| --- | --- | --- |
| `ORACLE_CLIENT_ACCEPTANCE_USERNAME` | 真实客户端验收所用的普通 VPN 账号 | 专用验收账号变更、停用或重新建立时；不要填管理后台用户名 |
| `ORACLE_CLIENT_ACCEPTANCE_PASSWORD` | 与上述 VPN 账号配套的密码 | 该账号密码轮换时，与用户名核对后更新 |

验收账号按约定应独立、配额受限。它测试真实登录、设备登记和流量，不是 SSH 或 OCI API 凭据。地址更换通过服务端目录下发，不必改变验收密码。

`GITHUB_TOKEN` / `github.token` 是 GitHub 为一次工作流临时提供的令牌，不是需要手工添加的 Environment Secret。地址提案仅获得建立配置分支/PR 的权限，不自动合并、不直接写 main。如果仓库禁止 Actions 创建 PR，工作流 Summary 会给出已生成分支的比较链接，由所有者在网页创建 PR，无需新建个人访问令牌。

## 工作流界面的临时参数

| 工作流/参数 | 用途 | 常用选择 |
| --- | --- | --- |
| Primary and backup IP settings / `mode=inspect` | 只读显示仓库期望目录和公共 DNS | 排查当前配置、核对 DNS 服务商时；输出不是 OCI 实时绑定证据 |
| 同上 / `mode=prepare` | 为已经在 OCI 准备好的新入口生成配置 PR，保留旧入口用于恢复 | 未来换 IP 的第一阶段 |
| 同上 / `mode=cutover` | OCI 已完成绑定交换后，更新私网映射并保持主、备入口分别使用各自 IPv4 出口 | 本轮新主 IP 交换到 `10.0.0.6` 后 |
| 同上 / `confirmed_bindings` | 确认已核对实际 OCI 绑定 | 仅在控制台逐项读回符合变量值后勾选；不会替你执行 OCI 变更 |
| Oracle authorized project operations / `operation` | 固定的服务器操作，如 preflight、deploy、logs、restart、rollback | 普通换 IP 使用地址提案流程，不需要手动输入服务器命令。`status` 是历史扩展网络观测，会采集约 5 分钟；不要把它当作快速连通性检查 |
| Oracle agent/service/CI 的 `operation` | 历史诊断代理及固定服务维护入口 | 仅按具体维护任务使用，不属于每次换 IP 的必做步骤 |

`REVISION`、`REV`、`OPERATION`、`REQUESTED_OPERATION`、`SCOPE_BASE`、`CI_KEY`、`KNOWN_HOSTS`、`GH_TOKEN` 等在 YAML 的步骤 `env` 中出现时，通常是工作流临时传入/映射的内部值。**不要照着它们再建立同名 Environment 变量**。地址工作流实际需要手工维护的是上表列出的 `PROXY_*`。

## 已完成迁移的历史步骤（不要重复执行）

1. rc34 已支持动态地址目录。先将四项 Variables 保存为已核对的准备阶段绑定：主 `152.67.154.225 → 10.0.0.220`，备用 `150.230.113.158 → 10.0.0.246`。
2. 在 OCI 网页完成新主 IP 与原主 IP 的交叉绑定并读回，保留 Reserved 对象，不点终止/删除。
3. 将 `PROXY_PRIMARY_PRIVATE_IPV4` 改为 `10.0.0.6`；其他三项保持不变。运行 `cutover`、勾选确认，核对生成的 PR 后合并。
4. 验证普通连接的新主入口与出口，更新现有 DNS 的 A 记录。DNS 记录在其实际托管平台管理；这些 Variables 不控制 DNS。
5. 确认其他仍在使用的客户端/FlClash 订阅已更新，再按精确清单释放旧公网 IP、无用辅助私网、未选中候选 IP 和临时诊断日志。主私网 IP、IPv6、生产安全规则不属于清理项。

当前仓库文档记录 Cloudflare 为既有 DNS 托管方；仍应以公共 NS 查询及实际账户中的域名为准。仅在 OCI 建立同名 DNS 区域不会自动迁移现有 DNS。


## 当前出口策略

当前主入口/IPv4 出口为 `152.67.154.225`（服务器私网 `10.0.0.6`），备用入口/IPv4 出口为 `150.230.113.158`（私网 `10.0.0.246`）。两条入口的权限、默认顺序在后台按账号设置；仍共享账号配额与限速。后续通过 Environment 地址提案更换 IP 时，工具保留这一配对策略。IPv6 仍共用原有出口。此策略调整无需重新发布客户端或生成 FlClash 链接/密钥；已有网络连接需重连后使用新的出口映射。
