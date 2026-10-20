# Oracle Proxy · Oracle 自托管管理后台

按用户要求，后台改为部署在现有 Oracle 服务器。不需要 Cloudflare Zero Trust、D1、Workers、
部署 Token 或绑定银行卡。Cloudflare 仅保留已有域名的 DNS 托管。

地址：`https://vpn-admin.morandi.dpdns.org`（部署后才可访问）。

## 实现与边界

- Django 5.2 LTS、django-allauth 的 GitHub OAuth/PKCE 与 TOTP 双重验证；不是自制 OAuth 协议实现。
- 默认只接受 GitHub 数字账号 ID `204281968`（Morandi-official）。邮箱不是授权依据。
- 首次登录强制绑定验证器；绑定后必须重新登录并通过动态码才能访问状态、审计及私有页面资源。
- 仅链接 GitHub 账号、旧会话或本地密码均不足以进入后台；不开放本地注册、密码重置或邮件登录。
- TOTP 与恢复信息使用独立 Fernet 密钥加密；加密密钥和 Django 会话密钥保存在 root-only 配置文件。
- SQLite 保存状态、会话、共享限速/防重放缓存及审计；无需第三方数据库。
- 本机 systemd 定时器每分钟用普通系统账号采集 wg0 服务、接口与 UDP 51820 监听信息。
- 无数据时显示未知，180 秒后显示过期，日志保留 30 天。Peer/流量/端口修改尚未接入。
- Gunicorn 仅监听 `127.0.0.1:8787`；Caddy 提供免费自动续期 HTTPS 证书。
- 应用、诊断进程均不拥有 root、sudo 或 Linux capabilities；网页不包含 SSH 或任意命令入口。

这是只读管理面首版，不代表完整 Windows VPN、防泄漏、UU 连续性和配置管理已经验收。

## GitHub 自动部署授权（推荐）

用户已授权扩大项目运维能力。完成 [项目管理员通道的一次性激活](../../ops/oracle-project/README.md) 后，
GitHub 可以预检环境、安装后台依赖、写入 OAuth 配置、部署/升级、配置 HTTPS、管理项目服务和回滚。
后续代码更新或固定 GitOps 请求可触发执行，减少手动 SSH 操作。
此通道信任 main 中的项目运维代码并以 root 执行；网页后台仍是无 sudo 的普通账号。
下面保留管理员直接安装的方式，作为初始激活前或人工恢复时的替代路径。

## 一次性账号操作

### 1. DNS

在 Cloudflare 现有 zone 添加记录：

| 类型 | 名称 | 内容 | 代理状态 |
| --- | --- | --- | --- |
| A | `vpn-admin` | `152.67.156.100` | DNS only / 灰云 |

这里沿用仓库已配置的 Oracle 地址。实际安装前须确认它仍是目标实例公网地址。

### 2. GitHub OAuth App（免费）

登录 GitHub，进入 **Settings → Developer settings → OAuth Apps → New OAuth App**：

- Application name：`Oracle Proxy Admin`
- Homepage URL：`https://vpn-admin.morandi.dpdns.org`
- Authorization callback URL：`https://vpn-admin.morandi.dpdns.org/accounts/github/login/callback/`

记录 Client ID，并生成 Client Secret。**Client Secret 只填写到 Oracle 的 root-only 配置，
不发送到聊天、GitHub 源码、Actions 日志或工单。** OAuth App 和域名要保持上述精确匹配。
不需要 Cloudflare Account ID、D1 UUID 或 Zero Trust 团队域名。

### 3. 主机预检与首次注册

现有 GitHub `oracle-ci` 密钥受 forced-command 限制，只允许已批准的诊断操作。
它不能安装 Python/Caddy、创建系统账号或注册新服务。当前没有扩展这个权限。
下面步骤由有管理员权限的现有 Oracle 会话执行一次；日常后台使用不需要 SSH。

先从本 PR 的成功 Actions 下载 `OracleProxy-Admin-Oracle-SelfHosted` Artifact，解压两层
（GitHub Artifact 外层 ZIP 和其中的源码 ZIP），保留 `SOURCE_REVISION` 与校验和。
也可在已审核的 Git 仓库 checkout 中使用完整提交 SHA。

```sh
python3 deploy/host.py preflight
```

该操作只输出 Python/架构/必需工具与端口占用概况，不读取私钥或变更系统。
主机需要 Python 3.11+、venv、systemd、runuser 和 Caddy。
Ubuntu/Debian 主机可通过系统包安装 `python3-venv` 和 `caddy`；
如现有主机已有 Web 服务，先根据预检结果决定如何集成，不能直接覆盖它的配置。

首次执行安装器：

```sh
sudo python3 deploy/host.py install
```

安装器先创建 `/etc/oracle-proxy-admin/admin.env`（root:root，0600）和随机密钥，然后退出，
提示配置 OAuth。使用 `sudoedit /etc/oracle-proxy-admin/admin.env` 仅替换以下占位值：

- `ADMIN_GITHUB_CLIENT_ID`
- `ADMIN_GITHUB_CLIENT_SECRET`

保留自动生成的 `ADMIN_SECRET_KEY`、`ADMIN_MFA_ENCRYPTION_KEY`。
不要给值加引号或空格。完成后再次执行相同安装命令。
从 Git checkout 而非 CI Artifact 安装时，必须提供 `--revision` 和经过核实的完整提交 SHA。

安装器会：创建独立服务/构建账号；以无特权构建账号安装固定版本依赖；
把代码和 venv 封为 root 所有；以应用账号执行迁移；注册服务；
切换版本并验证本机健康；启动失败时恢复上一版应用。
仅写入本产品的 `/opt/oracle-proxy-admin`、`/etc/oracle-proxy-admin`、
`/var/lib/oracle-proxy-admin` 与三个固定 systemd 单元。

### 4. HTTPS 入口

检查 `deploy/Caddyfile`。由管理员把其中的专用 host block 合并到现有 Caddy 配置；
若主机没有其他网站，可使用这份 host block 作为新配置。
安装器不会覆盖现有 Caddy/Nginx/Apache 配置。

```sh
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl reload caddy
```

Oracle VCN/NSG 和主机防火墙必须允许到此实例的 TCP 80、443，才能申请证书和访问 HTTPS。
不开放 8787；不调整现有 WireGuard UDP 端口、SSH 或其他代理规则。
仅在实际预检后为必要的 Web 端口添加规则，安装器不批量修改网络策略。

### 5. 登录验收

1. 打开 HTTPS 域名，确认浏览器信任证书。
2. 使用 Morandi-official GitHub 账号授权；其他账号应被拒绝。
3. 在验证器 App 扫码绑定动态码；保存一次性恢复码到自己控制的安全位置。
4. 退出并重新使用 GitHub + 动态码登录，确认状态、采集时间和审计记录。
5. 确认错误动态码、退出后访问 API、过期会话均被拒绝；确认外部访问 `/api/health` 返回 404。

## 本地和云端测试

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python manage.py collectstatic --noinput --settings config.test_settings
.venv/bin/python manage.py check --deploy --fail-level WARNING --settings config.test_settings
.venv/bin/python manage.py test console --settings config.test_settings
.venv/bin/python -m unittest discover -s deploy -p 'test_*.py' -v
```

测试配置只用于单独的测试进程；生产 WSGI 默认加载强制环境配置的 `config.settings`。
CI 同时测试 Python 3.11/3.12，并在一次性的 GitHub-hosted Linux VM 上实际注册普通用户 systemd 服务，
验证启动、升级、故意破坏新版 WSGI 后自动恢复上一版、显式回滚和代码目录权限。
该 root 测试入口 `ci_smoke.py` 不进入发布源码包，且拒绝在非授权 disposable runner 上执行。

GitHub OAuth HTTP 回包在自动化测试中被模拟；仍需真实 OAuth App、证书和账号完成最后登录验收。
云端 systemd 成功不能代替实际 Oracle 安装和现有服务兼容检查。

## 升级、回滚与备份

- 使用新的、通过 CI 的源码 Artifact 运行安装器。只有独立版本目录构建完成后才切换 current。
- 当前数据库迁移只新增本产品表；将来的升级必须保证旧版本仍能读取新结构。
- 应用健康检查失败会恢复上次 current；保留失败候选便于诊断，不复用同一版本标签。
- 手动应用回滚：`sudo python3 deploy/host.py rollback`。回滚保留数据库和身份密钥，
  不自动执行反向迁移或用旧数据库覆盖新审计/会话。
- 升级前应备份一致性的 SQLite 快照及 root-only `admin.env`，作为同一个恢复集。
  **只有数据库而没有 MFA 加密密钥不能恢复动态码。** 对不兼容数据库迁移必须另写并测试恢复方案。
- 验证器丢失时优先使用一次性恢复码；恢复码也丢失时由主机管理员执行人工身份恢复，
  不通过关闭 MFA、邮件链接或开放注册恢复后台访问。
- 诊断失败保留最后观测并标记过期，不会触发 VPN 重启或修改路由。

## 仍未交付

Peer 增删、逐设备用量、端口变更与服务端配置回滚仍需独立、固定动词的受限执行器。
现有后台刻意不拥有这些权限。本方案没有把浏览器变成 root 终端。
GitHub 目前构建和验证可安装源码包；新的项目管理员入口激活后可自动部署；激活前不声称 GitHub 已拥有真实服务器管理员权限。
