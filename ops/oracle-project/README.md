# GitHub → Oracle 项目管理员通道

用户已明确要求扩大 GitHub SSH 运维权限，减少每次部署都需要手动登录或询问。
本通道在专用账号 `oracle-project-ci` 上提供项目 root 运维能力；原有 `oracle-ci` 通道保留。

## 权限和信任范围

- 可执行环境预检、固定依赖安装、后台 OAuth 配置、后台部署/升级、专用 HTTPS 配置、
  项目服务启动/停止/重启、项目日志及应用回滚。
- SSH 命令只有固定 operation + 完整提交 SHA，禁用交互 shell、SFTP/SCP、PTY、端口/代理转发。
- sudo 只允许固定 root 入口；入口再次验证操作、SHA、sudo 调用账号，验证该 SHA 是指定仓库当前 main。
- 服务器通过验证 TLS 的 GitHub API/codeload 下载该提交，限制归档大小、条目、路径和文件类型，
  在 root-only 目录缓存；不执行 SSH 客户端上传的任意脚本。
- **重要的实际授权：main 中的项目运维 Python 会以 root 执行。因此 main 的写入者可以改变 root
  运维行为；这不是对 main 运维代码的操作系统沙箱。** 应把 main 和 `oracle-ops` Environment
  当成管理员边界保护。该权限扩大来自用户本次明确授权。
- 网页后台继续使用独立无 sudo 的系统账号，不能调用此入口；没有把 root 能力交给网页会话。

## 一次性激活

必须由现有 Oracle 管理员执行一次 bootstrap；GitHub 不能凭现有受限 SSH 密钥自行提权。
bootstrap 只读取旧 `oracle-ci` 账号的一个 **公钥**，复用 GitHub 中已有的 `ORACLE_CI_OPS_KEY`。
它不读取私钥、不修改旧账号、不修改/重启 sshd。
如果旧账号存在多个公钥，程序将停止，要求用 `--public-key-file` 明确选择。

下载经过 CI 的固定提交中的 `bootstrap.py`，保存到私有临时目录后，以 root 和 Python 隔离模式执行：

```sh
oracle_bootstrap_dir=$(mktemp -d)
curl -fsSL 'https://raw.githubusercontent.com/Morandi-official/Oracle-Proxy-Infrastructure/REVIEWED_SHA/ops/oracle-project/bootstrap.py' -o "$oracle_bootstrap_dir/bootstrap.py"
sudo python3 -I "$oracle_bootstrap_dir/bootstrap.py" --revision REVIEWED_SHA
```

`REVIEWED_SHA` 必须替换为已经通过 CI 的完整提交 SHA，不应直接执行未知分支或他人的脚本。
成功标记为 `ORACLE_PROJECT_CI_AUTHORIZATION=READY`。
前置条件是系统已有 Python 3、sudo/visudo，以及一个已工作的 `oracle-ci` 公钥授权。

安装的固定文件：

- `/usr/local/libexec/oracle-project/{ssh_entry.py,gate.py}`（root 所有）
- `/var/lib/oracle-project-ci/.ssh/authorized_keys`（root 所有，只有选定公钥和 forced command）
- `/etc/sudoers.d/oracle-project-ci`（root:root，0440，经 visudo 校验）
- 授权前的上述文件备份保存在 `/var/backups/oracle-project-authorization/`。

之后在 GitHub 仓库 **Settings → Environments → oracle-ops** 设置：

| 类别 | 名称 | 值 |
| --- | --- | --- |
| Secret | `ORACLE_ADMIN_GITHUB_CLIENT_SECRET` | 已创建 OAuth App 的 Client Secret |
| Variable | `ORACLE_PROJECT_AUTODEPLOY` | `true` |
| Variable（可选） | `ORACLE_ADMIN_GITHUB_CLIENT_ID` | `Ov23liYD7HIQdS5nDjpS`（工作流已有默认值） |

保留现有 `ORACLE_CI_OPS_KEY`、`ORACLE_CI_KNOWN_HOSTS`，并将 Environment 的允许部署分支限制到 main。
OAuth Secret 直接填入 GitHub 的 Secret 输入框，不发送聊天，不写 request.json 或源代码。
如果不想把 OAuth Secret 存入 GitHub，可一次性由主机管理员写入后台受保护配置，后续部署会保留它。

## 自动运维

工作流 `Oracle authorized project operations` 仅在 main 运行，使用原有 SSH 密钥和严格主机指纹。
在激活前，push 事件明确跳过实际服务器操作；手动 workflow_dispatch 可用于定点操作。

- main 上后台/运维代码更新，自动完成预检、必要依赖安装、配置、部署、HTTPS 配置和 HTTPS 检查。
- 更新 `ops/oracle-project/request.json` 可提交一个固定运维请求，也可与诊断代码修复一同提交。
  显式更新的请求优先于默认 deploy；例如：

```json
{"operation":"preflight","request_id":"preflight-20261020-01"}
```

请求文件只接受 operation 和非敏感 request_id，不能包含密钥、路径、参数或命令。
这样助手可通过有权限的 GitHub 提交发起预检、状态、日志或回滚，不需要让用户反复点击 Actions。
涉及 main 的提交本身就是管理员行为；不要给不可信来源 main 写入权限。

## 服务器行为与限制

- 自动安装器适配 apt 系 ARM64/x64。旧系统使用独立的 CPython 3.12.15
  （Astral python-build-standalone 20261013），缺少 Caddy 时安装官方 2.11.7 deb。
  两者均固定上游 URL 与 SHA256，不替换系统 Python、不添加第三方 apt 源。
  Python 安装于 `/opt/oracle-proxy-python-3.12.15`，与应用版本回滚独立。
- GitHub API 和 codeload 需要服务器可访问；API 限流或验证失败时停止，不退回未验证来源。
- 配置通过 SSH stdin 传输，只允许 OAuth 的 Client ID/Secret，不接受其他环境变量。
  原有 Django/MFA 密钥保留；root-only 日志导出时对已知密钥脱敏。
- HTTPS 配置添加专用 Caddy import/snippet，保存原配置；校验或 reload 失败时恢复原文件。
  现有同名 host 配置冲突会停止，不覆盖未知网站。
- 不自动删除或重写现有 WireGuard Peer、SSH 配置、路由、DNS 或防火墙。
  后续确有项目网络需求时，可在可信 main 中增加经过测试的特定操作。
- 操作结果元数据写入 root-only `/var/lib/oracle-project-ops/audit.jsonl`，不写请求正文或密钥。
- 已完成的网页 root-only 配置、备份和实际主机权限不能由云端构建成功替代，需激活后验证。

## 撤销

管理员可移除该专用 sudoers 文件并把 `oracle-project-ci` shell 改为 nologin，撤销新增通道：

```sh
sudo rm /etc/sudoers.d/oracle-project-ci
sudo usermod --shell /usr/sbin/nologin oracle-project-ci
```

原有 `oracle-ci` 通道、现有代理和网页普通用户服务不依赖该新增 SSH 授权继续运行。
恢复授权文件时仅从 root-only 备份还原本产品固定路径，并使用 visudo 校验。

## 测试

纯测试覆盖 SSH 参数注入、sudo 入口二次校验、非当前 main 拒绝、归档穿越/链接/超限、
多公钥拒绝、配置字段/换行注入、GitOps 请求白名单和 Caddy 失败回滚。
disposable GitHub CI 另行验证真实 SSH 公钥认证、forced-command 拒绝、sudo 限制、
实际 root 运维进程委派（仅模拟 GitHub 传输）、Secret 配置保密和现有后台生命周期。
测试使用临时合成密钥，不访问真实 Oracle，不上传私钥。
