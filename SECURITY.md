# AutoSec Guard – 安全设计与企业部署指南

本文档记录产品的安全架构决策、已知风险、以及企业/实验室环境下的部署加固清单。

---

## 1. 产品安全定位

AutoSec Guard 是一款**车载信息娱乐系统（ICV）漏洞扫描平台**，设计为**实验室边缘工作站**运行模式：

| 维度 | 设计决策 | 说明 |
|------|---------|------|
| 部署模式 | 单机/局域网边缘 | 不依赖公网云服务 |
| 认证模型 | 可选 JWT | 本地模式可关闭强制认证；网络模式强制开启 |
| 数据存储 | SQLite（默认） / PostgreSQL | 边缘本地足够；多用户切换 PostgreSQL |
| AI 密钥 | 用户自持，服务端 Fernet 加密存储 | 服务器不持有共享 AI 账号 |
| 数据库迁移 | Alembic / flask-migrate | 版本化 schema 升级，防止数据丢失 |

---

## 2. 安全控制清单

### 2.1 认证与授权

- **JWT 令牌**：使用 HS256 签名，令牌有效期 24 小时
- **密码哈希**：bcrypt（cost factor ≥ 12）
- **端点认证**：
  - `@token_required`：管理类端点（用户管理、审计日志）强制认证
  - `@execution_auth_optional`：执行类端点（run_poc、auto_discovery 等）可通过 `AUTOSEC_REQUIRE_AUTH` 控制
  - `@admin_required`：管理员专属端点额外校验 role
- **登录防暴力**：内存速率限制，10 次失败/60 秒后封禁该 IP 60 秒，返回 429

#### 首管理员 Bootstrap（系统初始化）

| 模式 | 环境变量 | 行为 |
|------|---------|------|
| 边缘 Web 初始化（默认） | `AUTOSEC_BOOTSTRAP_MODE=edge` | 空库时登录页显示「系统初始化」，创建首管理员；之后关闭自助注册 |
| 企业 CLI 初始化 | `AUTOSEC_BOOTSTRAP_MODE=cli_only` | 禁止 Web 创建管理员；执行 `flask create-admin --username <name>` |
| 防抢注 Token | `AUTOSEC_BOOTSTRAP_TOKEN=<随机串>` | Web 初始化须携带 token（网络暴露时强烈推荐） |
| 开放注册 | `AUTOSEC_ALLOW_OPEN_REGISTRATION=true` | 已有管理员后允许自助注册（仅演示/培训环境） |

- 首管理员创建写入审计日志（`bootstrap_admin_created`）
- 前端通过 `GET /api/auth/status` 感知 bootstrap 状态，不再显示误导性 Register 入口

### 2.2 网络暴露

- **默认监听地址**：`127.0.0.1`（仅本机），通过 `AUTOSEC_HOST=0.0.0.0` 扩展到局域网
- **CORS**：通过 `AUTOSEC_CORS_ORIGINS` 配置允许来源；未设置时仅在 `AUTOSEC_HOST=127.0.0.1` 场景安全
- **生产必须**：前置 Nginx + TLS，参见 `docs/nginx-tls.conf`

### 2.3 PoC 执行安全

- **沙箱隔离**：PoC 在独立子进程中运行（`start_new_session=True`），与主服务进程隔离
- **目标范围校验**：`run_poc` / `fingerprint` / `agent-scan` 均校验目标 IP 是否在授权网段
- **出站网络限制**：未指定 `target_ip` 时沙箱拒绝所有出站连接
- **破坏性 PoC 审批**：`allow_disruptive` 默认 `false`；审批 token 一次性使用，TTL 300s
- **人工判定**：`/api/poc_manual_verdict` 强制 JWT 认证；Agent 模式弹出 UI 等待操作员确认，不自动伪造结论
- **Weaponize Agent**：LLM 生成代码仅写入 `/tmp/autosec_sandbox/`，禁止覆盖仓库 PoC 文件

### 2.4 敏感数据保护

- **AI API Key**：Fernet 对称加密存储；登录/Profile 接口仅返回 `apiKeyConfigured` 标志，不回传明文；前端 localStorage 永不持久化密钥
- **Agent/报告请求**：浏览器不再在请求体中传输 `api_key`，服务端从加密存储加载
- **PDF 导出**：所有报告导出路径使用 `escapeHtml` / `markdownToSafeHtml` 防 XSS

### 2.5 数据库

- **迁移机制**：Alembic（flask-migrate），启动时自动检测并执行待处理迁移
- **首次部署**：自动 `db.create_all()` 建表，并打印初始化 Alembic 的提示
- **备份建议**：生产每日备份 `autosec.db`；PostgreSQL 建议 WAL 归档

---

## 3. 网络部署模式对比

| 项目 | 本地边缘模式（默认） | 实验室网络模式 | 生产/企业模式 |
|------|-------------------|--------------|-------------|
| `AUTOSEC_HOST` | `127.0.0.1` | `0.0.0.0` | `127.0.0.1`（Nginx 代理） |
| `AUTOSEC_REQUIRE_AUTH` | `false` | `true` | `true` |
| `AUTOSEC_CORS_ORIGINS` | 未设置（`*`） | 指定局域网 IP | 指定域名 |
| TLS | 不需要 | 建议 | **必须** |
| 数据库 | SQLite | SQLite / PG | PostgreSQL |
| `AUTOSEC_SECRET_KEY` | 临时随机 | 固定配置 | **固定配置，必须** |

---

## 4. 生产部署加固清单

在正式对外提供服务前，逐项确认：

### 4.1 必须完成（CRITICAL）

- [ ] 配置 `AUTOSEC_SECRET_KEY`（≥32 字节随机字符串）
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] 将 `AUTOSEC_BOOTSTRAP_MODE` 设为 `cli_only`，用 CLI 创建首管理员：
  ```bash
  cd server && FLASK_APP=server.py flask create-admin --username admin
  ```
- [ ] 若必须使用 Web 初始化，设置 `AUTOSEC_BOOTSTRAP_TOKEN`（生成方式同上）
- [ ] 部署 TLS 证书（Let's Encrypt 或企业 CA）
  - 参见 `docs/nginx-tls.conf`
- [ ] 设置 `AUTOSEC_REQUIRE_AUTH=true`
- [ ] 设置 `AUTOSEC_CORS_ORIGINS` 为实际域名
- [ ] 备份现有数据库后执行 Alembic 初始化（如从旧版升级）：
  ```bash
  cd server/
  flask db init && flask db migrate -m init && flask db upgrade
  ```

### 4.2 强烈建议（HIGH）

- [ ] 将 `AUTOSEC_HOST` 设置为 `127.0.0.1`，通过 Nginx 反向代理
- [ ] 配置防火墙，仅允许 80/443 入站（关闭 5002 直接暴露）
- [ ] 启用 Nginx 访问日志，定期检查异常 IP
- [ ] 生产环境使用 PostgreSQL 替代 SQLite（多用户/高并发）：
  ```
  AUTOSEC_DB_URI=postgresql+psycopg2://user:pass@localhost:5432/autosec
  ```
- [ ] 定期轮换 `AUTOSEC_SECRET_KEY`（轮换后在线用户需重新登录）

### 4.3 建议（MEDIUM）

- [ ] 配置 `AUTOSEC_MAX_CONCURRENT_POCS`（推荐 3–5，根据服务器资源）
- [ ] 配置 `SANDBOX_CPU_SECONDS`（根据最慢 PoC 的实测时间设置）
- [ ] 定期检查 `server/logs/autosec.log`（日志轮转已配置：20MB × 5 个备份）
- [ ] 审查 `AuditLog` 表中的高危 PoC 执行记录
- [ ] 限制部署服务器的 SSH 访问

---

## 5. 已知设计权衡（非缺陷）

| 问题 | 当前设计 | 说明 |
|------|---------|------|
| `SECRET_KEY` 未配置时随机生成 | 重启后 JWT 全部失效 | 生产配置固定密钥即解决 |
| SQLite 无并发写优化 | 写入串行 | 边缘单用户场景完全够用；企业切 PostgreSQL |
| AI API Key 经前端传输 | HTTPS 下安全 | 服务端加密存储后无需每次传输；前端仅在保存时传递 |
| 本地模式 CORS `*` | 仅在 127.0.0.1 绑定时安全 | 网络部署必须设置 `AUTOSEC_CORS_ORIGINS` |

---

## 6. 漏洞报告

如发现安全问题，请通过以下方式负责任披露（Responsible Disclosure）：

1. **不要**公开创建 GitHub Issue
2. 发送详情至产品负责人邮箱（请联系仓库维护者获取）
3. 我们承诺在 72 小时内确认，30 天内提供修复版本

---

*最后更新：2026-07-09*
