# AutoSec Guard – 安全设计与企业部署指南

本文档记录产品的安全架构决策、已知风险、以及企业/实验室环境下的部署加固清单。

---

## 1. 产品安全定位

AutoSec Guard 是一款**车载信息娱乐系统（ICV）漏洞扫描平台**，设计为**实验室边缘工作站**运行模式：

| 维度 | 设计决策 | 说明 |
|------|---------|------|
| 部署模式 | 单机/局域网边缘 | 不依赖公网云服务 |
| 认证模型 | 强制持久会话 / Scoped API Token | 浏览器使用 HttpOnly Cookie；CLI 使用可撤销不透明 Token |
| 数据存储 | SQLite（默认） / PostgreSQL | 边缘本地足够；多用户切换 PostgreSQL |
| AI 密钥 | 用户自持，服务端 Fernet 加密存储 | 服务器不持有共享 AI 账号 |
| 数据库迁移 | Alembic / flask-migrate | 版本化 schema 升级，防止数据丢失 |

---

## 2. 安全控制清单

### 2.1 认证与授权

- **浏览器会话**：服务端持久会话 + HttpOnly / SameSite=Strict Cookie，默认有效期 12 小时
- **CLI Token**：数据库仅保存哈希，绑定用户、作用域、有效期与唯一 JTI，可列出和撤销
- **密码哈希**：bcrypt（cost factor ≥ 12）
- **端点认证**：
  - `@token_required`：所有目录、执行、证据、报告和管理端点强制认证
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
- 前端通过 `GET /api/v1/auth/status` 感知 bootstrap 状态，不再显示误导性 Register 入口

### 2.2 网络暴露

- **默认监听地址**：`127.0.0.1`（仅本机），通过 `AUTOSEC_HOST=0.0.0.0` 扩展到局域网
- **CORS**：默认关闭并使用同源 UI；仅显式配置 `AUTOSEC_CORS_ORIGINS` 时开启凭据跨域
- **生产必须**：前置 Nginx + TLS，参见 `docs/nginx-tls.conf`

### 2.3 PoC 执行安全

- **沙箱隔离**：PoC 在独立子进程中运行（`start_new_session=True`），与主服务进程隔离
- **目标范围校验**：`run_poc` / `fingerprint` / `agent-scan` 均校验目标 IP 是否在授权网段
- **出站网络限制**：未指定 `target_ip` 时沙箱拒绝所有出站连接
- **破坏性 PoC 审批**：`allow_disruptive` 默认 `false`；审批 token 一次性使用，TTL 300s
- **人工判定**：`/api/v1/sessions/{id}/reviews` 强制认证并形成持久事件；Agent 模式等待操作员确认，不自动伪造结论
- **探测生成 Agent**：LLM 只能选择注册探测器的声明式协议配置，不生成、不落盘、不执行模型代码

### 2.4 敏感数据保护

- **AI API Key**：Fernet 对称加密存储；登录/Profile 接口仅返回 `apiKeyConfigured` 标志，不回传明文；前端 localStorage 永不持久化密钥
- **Agent/报告请求**：浏览器不再在请求体中传输 `api_key`，服务端从加密存储加载
- **PDF 导出**：所有报告导出路径使用 `escapeHtml` / `markdownToSafeHtml` 防 XSS

### 2.5 数据库

- **迁移机制**：Alembic（flask-migrate），启动时自动检测并执行待处理迁移
- **首次部署**：通过 Alembic 创建版本化 schema；旧 SQLite 自动备份后迁移
- **失败策略**：迁移或回填失败时回滚、恢复备份并拒绝启动，不允许静默 `create_all()` 掩盖错误
- **备份建议**：生产每日备份 `autosec.db`；PostgreSQL 建议 WAL 归档

---

## 3. 网络部署模式对比

| 项目 | 本地边缘模式（默认） | 实验室网络模式 | 生产/企业模式 |
|------|-------------------|--------------|-------------|
| `AUTOSEC_HOST` | `127.0.0.1` | `0.0.0.0` | `127.0.0.1`（Nginx 代理） |
| 业务端点认证 | 强制 | 强制 | 强制 |
| `AUTOSEC_CORS_ORIGINS` | 留空（同源） | 指定局域网来源 | 指定域名 |
| TLS | 不需要 | 建议 | **必须** |
| 数据库 | SQLite | SQLite / PG | PostgreSQL |
| 安装级密钥 | 首次启动持久生成 | 持久生成/显式配置 | **持久且安全备份** |

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
| 未显式配置密钥 | 首次启动在用户数据目录生成 | 与数据库一起备份即可持续解密 |
| SQLite 无并发写优化 | 写入串行 | 边缘单用户场景完全够用；企业切 PostgreSQL |
| AI API Key 经前端传输 | HTTPS 下安全 | 服务端加密存储后无需每次传输；前端仅在保存时传递 |
| CORS 留空 | 不发送跨域允许头 | 同源前端不受影响 |

---

## 6. 漏洞报告

如发现安全问题，请通过以下方式负责任披露（Responsible Disclosure）：

1. **不要**公开创建 GitHub Issue
2. 发送详情至产品负责人邮箱（请联系仓库维护者获取）
3. 我们承诺在 72 小时内确认，30 天内提供修复版本

---

*最后更新：2026-07-09*
