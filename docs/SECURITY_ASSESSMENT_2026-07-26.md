# AutoSec Guard 客户发行安全测评与加固记录

测评日期：2026-07-26  
范围：React 客户端、Flask/WSGI 服务、PoC 执行边界、离线许可证、数据与密钥、Python/npm 依赖、Nuitka 构建和 GitHub Actions 发行链。

## 结论

当前工作树中的可复现高危产品缺陷已完成代码加固，完整后端测试 149 项通过，前端 10 项测试、类型检查和生产构建通过，Bandit 核心代码 HIGH/MEDIUM 为 0，PyPI 与 npm 在线漏洞库均报告 0 个已知漏洞。真实 macOS ARM64 Nuitka onefile 包已完成 20 项客户黑盒全链路验收。

仓库在完成以下两项外部处置前不得标记为“可发行”：

1. 轮换所有曾提交到 Git 的 API Key 和应用密钥；
2. 经仓库所有者批准后重写远端 Git 历史，永久移除旧 `.env`、`.env old`、数据库备份和实验配置中的秘密。

此外，当前旧许可证签发私钥是明文文件。首次签发前必须按 `docs/OFFLINE_LICENSING.md` 的 `protect-key` 流程迁移到离线加密保险库并删除明文副本。

## 已修复发现

| 严重度 | 发现 | 加固结果 |
|---|---|---|
| Critical | PoC 子进程继承服务端会话、AI、许可证等全部环境秘密 | 改为最小环境白名单 |
| Critical | onefile 通过环境变量向 PoC 子进程传递 Base64 源码，且许可证上下文未跨子进程 | 改为只传内置 PoC 名称并从编译注册表加载；只传许可定位信息，验证后清除；任意外部脚本拒绝执行 |
| Critical | SSH 密码和审批令牌通过进程命令行暴露 | 参数改由 stdin 传递，审批令牌不进入子进程 |
| Critical | 客户可提交 `lab_command` 或任意 `AUTOSEC_*` 执行/覆盖环境 | 删除自由命令能力；仅保留固定 `id` 证明；禁止通用环境注入 |
| High | 客户可覆盖 CPU、内存、句柄、输出和超时限制 | 全部改为服务端策略并设置上下界 |
| High | 文件型参数可读取客户主机任意文件 | 仅允许设备数据目录 `fixtures/` 下的已存在路径 |
| High | 普通用户可以自行签发破坏性执行审批 | 审批端点改为管理员专属 |
| High | 发行包可通过环境变量开启任意 Python 脚本执行 | 编译发行包永久禁用该接口 |
| High | 破坏性本地主机 EXP 默认可运行 | 客户包默认关闭；仅隔离实验机显式启用 |
| High | Web 首管理员在网络暴露时可能被抢注 | 非回环监听缺少 CLI 初始化或强 token 时拒绝启动 |
| High | Host/Forwarded Host 可影响 CSRF 来源判断 | 默认不信任转发头；非回环来源必须精确配置 |
| High | AI URL SSRF 对 HTTPS fake-IP、链路本地地址放行过宽 | fake-IP 改为显式开启；链路本地始终拒绝；禁用重定向 |
| High | SSH 自动接受未知主机密钥 | 改为系统 known_hosts + 严格校验 |
| High | 仓库跟踪明文秘密和包含客户/运行数据的 SQLite 备份、WAL/SHM | 当前树删除并加入发行秘密门禁；本机完整数据库副本移入忽略目录 |
| High | PostCSS 路径穿越漏洞 | 升级至 8.5.23；npm audit 0 漏洞 |
| Medium | 密码仅 8 字符且管理员重置缺少一致校验 | 统一至少 12 字符、最多 72 UTF-8 字节 |
| Medium | 修改密码后旧会话和 API Token 仍有效 | 密码变更/重置时全部撤销 |
| Medium | Flask 开发服务器用于客户运行时 | 改为 Waitress 3.0.2 生产 WSGI |
| Medium | 500 响应泄露内部异常和路径 | API 5xx 统一通用错误和追踪编号 |
| Medium | 敏感 API 响应可能缓存，数据库权限依赖系统默认值 | API `no-store`；POSIX 数据/密钥/许可证强制 0600 |
| Supply chain | Actions 使用可移动标签、默认 PyInstaller、权限过宽 | 固定 40 位 SHA、强制 Nuitka、最小权限、安全门、校验和及 provenance |
| Commercial IP | 客户包可能回退为易提取字节码的 PyInstaller，前端调试映射缺少发行门禁 | 禁止回退；Nuitka onefile + LTO + 去 docstring/assert；禁用 source map；发行内容扫描源码、映射和私钥 |
| Packaging | Nuitka 排除 SQLAlchemy 方言导致 Alembic 启动失败；迁移脚本不能以源码数据交付 | 保留必需方言；客户包使用编译内置、版本受控且失败恢复的增量 schema 升级，不携带迁移 `.py` |

## 发行门禁

GitHub CI 在构建前执行：

- 完整 Python 测试；
- 前端测试、类型检查和生产构建；
- `pip-audit`、`npm audit`；
- Bandit 核心与 PoC 分层扫描；
- 跟踪文件秘密模式、敏感扩展名、SSH 弱校验、自由本地命令及 Action SHA 检查；
- Nuitka standalone 四平台构建、未授权包烟雾测试；
- SHA-256 校验文件和 GitHub artifact provenance。

## 运行安全要求

- 默认只监听 `127.0.0.1`。跨主机访问必须使用 TLS 反向代理、`AUTOSEC_BEHIND_TLS=true`、CLI 初始化或强 bootstrap token，以及精确 UI Origin 白名单。
- SSH 探测前先由管理员把经核验的目标主机密钥加入运行账号的 `known_hosts`。
- 测试文件先复制到 `AUTOSEC_DATA_DIR/fixtures/`，API 只提交该目录内的相对路径。
- `AUTOSEC_ENABLE_HOST_EXPLOITS=true` 只能在可还原、网络隔离、无生产秘密的实验工作站使用。
- 离线授权无法实时撤销，也不能抵御拥有客户设备管理员权限并可任意修改二进制/系统时间状态的专业攻击者；需要实时撤销时应增加在线授权服务或硬件可信时间/TPM。

## 验证结果

- Python：149/149 通过。
- 前端：10/10 通过；TypeScript 通过；Vite production build 通过。
- 客户黑盒：20/20 通过；覆盖 ZIP 摘要、安装、首启、许可、AI 隐私、安全本地检测、持久化与重启。
- Bandit 核心：HIGH 0、MEDIUM 0。PoC 层除明确的受控本地 shell 执行规则外，HIGH 0。
- `pip-audit`：0 个已知漏洞。
- `npm audit`：0 个已知漏洞（371 个依赖）。
- 当前跟踪工作树秘密扫描：通过。
