# Oracle Proxy · Cloudflare 管理后台（只读首版）

当前实现是真实的服务诊断和访问审计基础，不是完整 VPN 管理产品。
后台源码独立于 Windows 客户端，不包含 SSH 私钥、WireGuard 私钥或任意命令入口。

## 已实现

- 中文响应式管理界面：Oracle 服务、接口、UDP 51820 监听、采集时间、审计记录。
- Cloudflare Access JWT 的 RS256 签名、issuer、audience、有效期、应用类型与管理员邮箱白名单校验。
- 静态资源也必须认证；禁用 workers.dev、预览地址和缓存。CSP 不允许第三方脚本或内联脚本。
- GitHub Actions 通过已有 forced-command `agent-status` 读取诊断，再 HMAC-SHA256 上报 Worker。
- 限制报告字段、正文大小、节点、时钟窗口，拒绝额外字段和重复 ID。D1 原子批处理防止半写入。
- 按观测时间显示最新报告，180 秒后明确标记过期，30 天自动清理；没有数据时显示未知。
- Peer、流量和配置修改尚未接入，界面明确显示未开放，API 不接受写操作。

## 账号与一次性配置

拟用域名：`vpn-admin.morandi.dpdns.org`；管理员：`morandi@nuaa.edu.cn`。
Cloudflare 账号通过 GitHub 登录，与后台的 Access 登录是两套独立认证。
当前代码没有实现 GitHub OAuth；后台由 Cloudflare Access 和你选择的身份提供商认证。

在 **Cloudflare Zero Trust** 创建 Self-hosted Access 应用，保护上述完整主机名：

1. 选择身份提供商，将管理员限制为上述邮箱，并在 IdP/Access 中要求 MFA 或硬件密钥。
   应用不能配置 Everyone Allow；邮箱 OTP 本身不能当作已验证 MFA。
2. 记录团队 issuer（形如 `https://TEAM.cloudflareaccess.com`）和此应用的 AUD。
3. 为**精确路径** `/api/ingest` 建立更具体的 Access Bypass 应用，使机器报告到达 Worker。
   这条路径仍由 Worker 的独立 HMAC 验证；不要给整个域名设置 Bypass。
   部署后验证相邻路径和 HTML 仍需要 Access；推荐对机器路径配置 WAF 速率限制。
4. 在账号内创建名为 `oracle-proxy-admin` 的 D1 数据库，记录 Database ID。
5. 创建账号范围受限的 Cloudflare API Token，供 GitHub Actions 部署 Worker、D1 迁移和自定义域名。
   不使用 Global API Key；仅授权目标账号/域名所需的 Workers Scripts、D1 和 Workers Routes 权限。
   因 Cloudflare 账号权限设置不同，以 Cloudflare 对该自定义域名绑定所要求的最小权限为准。

不要把 Token、SSH 私钥或 HMAC 密钥粘贴进聊天或提交仓库。

## GitHub 配置和部署

创建 GitHub Environment `cloudflare-admin`，仅允许受保护的 `main` 部署。
Environment Variables：

| 名称 | 值 |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | 你的账号 ID |
| `ADMIN_PUBLIC_ORIGIN` | `https://vpn-admin.morandi.dpdns.org` |
| `ADMIN_ACCESS_ISSUER` | Access 团队 HTTPS issuer |
| `ADMIN_ACCESS_AUD` | 此 Access 应用的 64 位十六进制 AUD |
| `ADMIN_EMAILS` | `morandi@nuaa.edu.cn` |
| `ADMIN_D1_DATABASE_ID` | D1 数据库 ID |

Environment Secrets：`CLOUDFLARE_API_TOKEN`、`ADMIN_INGEST_HMAC_KEY`。
HMAC 密钥应为安全随机的 32 字节、编码为 64 个小写十六进制字符。

已有 `oracle-ops` Environment 保留现有 `ORACLE_CI_OPS_KEY` 和 `ORACLE_CI_KNOWN_HOSTS`：

- 添加相同值的 Secret `ADMIN_INGEST_HMAC_KEY`。
- 添加 Variable `ADMIN_INGEST_URL=https://vpn-admin.morandi.dpdns.org/api/ingest`。

合并代码后，Actions 依次手动运行：

1. **Deploy Cloudflare administrator console**：校验配置，执行增量 D1 迁移，配置签名密钥并部署。
2. **Forward restricted Oracle status to administrator console**：调用现有 `agent-status` 并上报。
3. 访问域名，验证登录、三项真实诊断、审计和过期提示。手动采集不会形成持续在线监控；
   后续确认运行成本与访问策略后再启用定时采集或 Oracle 主动上报。

GitHub 运维密钥仅保存在 Actions Environment，浏览器和 Worker 都无法取得。
Oracle 侧无需为这一版本开放 HTTP 管理端口，也不修改 wg0、Peer、路由或防火墙。

## 本地验证

需要 Node.js 24、Python 3；依赖版本及完整锁文件已提交。

```sh
npm ci
npm run check
npm test
python3 -m unittest discover -s test -p 'test_*.py' -v
npm run build -- --config wrangler.example.jsonc
npm run test:runtime
```

CI 的 SQLite 测试执行真实迁移与查询，并模拟 D1 的事务批处理接口；不代表云端 D1 已部署。
另外的 workerd/Miniflare 集成测试运行实际 Worker 包和本地 D1，验证上报、重放事务和未登录拒绝。
打包验证不需要 Cloudflare 凭据，不会发布网站。缺少浏览器工具时不声称完成浏览器视觉验收。

## 回滚、密钥轮换与限制

- 回滚 Worker 到已知正常版本：在 Cloudflare Workers Deployments 选择该版本回滚，
  或使用对应版本的 `wrangler rollback`。此版本数据库只有新增表，不通过删除数据库回滚。
- 所有部署应保留原 Worker 版本和 D1 恢复点；后续结构变更必须另写兼容性与恢复方案。
- HMAC 密钥轮换须同步更新两个 GitHub Environment，再运行部署和上报；短暂不匹配将拒绝报告，
  UI 保留最后观测并提示过期，不影响 VPN 数据平面。
- 若凭据泄漏，先撤销该凭据，暂停转发，再配置新密钥；不要为恢复可用性关闭 Access 校验。
- 30 天审计属于应用层记录，不是不可篡改存证；Cloudflare/GitHub 管理员仍能改动应用和数据库。
- 仅报告服务、接口、端口存在性。它不查询 Peer、公钥、真实握手、流量或公网出口，
  也不能证明 Windows 防泄漏与 UU 兼容。

## 下一阶段接口

Peer 增删和端口调整必须经 Oracle 上的 root 所有、固定动词的受限执行器。
流程应包含：权限校验、版本比较、预检、只修改本产品拥有的配置、持久化备份、应用、
独立连通性检查和超时回滚。浏览器不得提交 shell、脚本、服务名或任意文件路径。
在该执行器和测试完成前，本版保持只读。
