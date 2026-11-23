# Local SSH MCP

项目包括两个可独立运行的服务。Python 服务提供托管终端和并行执行，原 TypeScript 服务继续提供 SSH 密钥管理页面及预定义只读操作。

## Persistent Terminal MCP

Python 3.12+ 服务使用 FastMCP、AsyncSSH 和 SQLite。连接配置、终端和执行任务各有独立 ID。每个托管终端维护一条 SSH 连接，其上的交互式 PTY 和独立命令使用不同 Channel。默认 HTTP 入口为 `http://127.0.0.1:8766/mcp`。

### 启动与更新

```bash
cp .env.example .env
bash deploy-terminal.sh install
curl -fsS http://127.0.0.1:8766/health
bash deploy-terminal.sh status
```

脚本使用 Linux 用户级 systemd 和 `uv`，支持 `start`、`stop`、`restart`、`status`、`logs` 与 `update`。传入新版本源文件后执行 `update`。开发时也可直接运行 `uv run --locked terminal-mcp migrate` 和 `uv run --locked terminal-mcp serve`。启动会检查数据库版本，执行初始迁移，并重新标记旧进程的 SSH 和普通任务状态。一个数据目录只运行一个服务进程。

### 身份和 SSH 凭据

通过 `uv run --locked terminal-mcp token` 生成 Agent Bearer Token。将哈希保存在 `.data/terminal/principals.json`，将原始令牌交给该 Agent 的客户端。验证时按请求重新读取配置。旋转令牌时替换哈希并保留 `owner_id`，该 Agent 的历史终端仍可发现。

```json
[
  {
    "owner_id": "ops",
    "token_sha256": "<生成的 SHA-256 哈希>",
    "targets": ["server.example.internal"],
    "credentials": ["web_key"],
    "workspaces": ["default", "staging"],
    "shell": false,
    "commands": {"uptime": ["uptime"], "disk_usage": ["df", "-h"]}
  }
]
```

默认只允许配置中明确列出的主机、凭据和工作区。受限身份只用 `operation` 执行上面配置的命令；显式设置 `shell: true` 才授予完整 Shell 和自定义命令。互不信任的完整 Shell 身份应使用独立的远端 Unix 账号。相同账号的进程共享该远端账号的权限。嵌入部署可向 `build_app(..., approve=回调)` 传入异步审批策略，拦截 Shell 输入或独立执行。

在 `.data/terminal/credentials.json` 维护凭据引用。可使用已有密钥管理页面生成的私钥文件，示例路径需按实际部署位置修改。

```json
{
  "web_key": {"kind": "key", "file": "/home/operator/ssh-mcp/.data/keys/web_readonly/identity"}
}
```

凭据清单、私钥和加密文件使用 `0600`，数据目录使用 `0700`。SSH Agent 登录需配置 `PTMCP_SSH_AGENT_PATH`，授权该 Principal 的 `ssh_agent`，并使用 `auth_type: "agent"`。密码或需要加密保存的无口令私钥可以由维护者离线加密。

```bash
uv run --locked terminal-mcp master-key .data/terminal/master.key
uv run --locked terminal-mcp encrypt .data/terminal/master.key .data/terminal/web-password.enc
```

在 `.env` 设置 `PTMCP_MASTER_KEY_FILE`，凭据种类使用 `password` 或 `encrypted_key`。加密私钥时传入 `--key-file 私钥路径`。分别备份主密钥和凭据文件。轮换时先用新主密钥重新加密各项凭据，再切换文件路径并重启。Profile 与凭据使用引用关联，多个 Profile 可以共享同一引用。已打开的 SSH 连接会在下次重连时使用新凭据。

在 `PTMCP_KNOWN_HOSTS` 预设目标主机公钥。先通过可信渠道取得管理员提供的主机指纹，使用 `ssh-keygen -lf 主机公钥文件` 核对，再加入 `known_hosts`。非默认端口的记录使用 `[主机]:端口`。未知或变化的主机密钥返回 `HOST_KEY_UNVERIFIED`。

### MCP 工作流程

在 SSH 管理页的「SSH 连接」中可新增、编辑、测试和删除连接。先在 TypeScript 的 `admin` 配置中设置 `terminalAdminPort: 8766`，再在 Python 服务的 `.env` 设置 `PTMCP_WEB_ADMIN_TOKEN_FILE` 和 `PTMCP_MANAGED_KEYS_DIR`，分别指向页面的管理员令牌文件和 SSH 密钥库。两个服务需在同一主机运行，并能读取各自配置所引用的文件。

选择「管理面板」可使用密钥库中的私钥。若要让某个 Agent 在 MCP 中发现和使用连接，请在新增时选择对应的 Agent 身份，该身份须已获目标和凭据授权。授权密钥库中的私钥时使用 `managed_密钥ID`。网页测试会校验终端服务的 `known_hosts`。

| 操作 | 工具与参数 |
|---|---|
| 添加与检查连接 | `connection_create` 传 `name`、`host`、`port`、`username`、`auth_type`、`credential_ref` 和可选 `tags`。再以返回的 `profile_id` 调用 `connection_test` |
| 查找与维护连接 | `connection_list` 支持 `name`、`host`、`tag`、`page` 和 `limit`。用 `connection_get` 查看详情，`connection_update` 传 `changes`，`connection_delete` 删除闲置配置 |
| 创建与切换终端 | `terminal_create` 使用 `profile_id`、`name` 和 `workspace_id`。用 `terminal_list` 发现已有会话，再用 `terminal_activate` 切换工作区默认终端 |
| 操作持续 Shell | `terminal_send` 传 `input: "cd /tmp\nexport DEMO=hello\n"`。后续发送 `"pwd\necho $DEMO\n"` 会沿用该 Shell。用 `terminal_signal` 发送 `CTRL_C` 或 `CTRL_D`，用 `terminal_resize` 调整尺寸 |
| 并行执行 | 调用多个 `terminal_exec`。完整权限使用 `command` 和可选绝对 `cwd`，受限权限使用命名的 `operation`。普通命令和持续 Shell 互不切换工作目录 |
| 执行长任务 | 设置 `yield_time_ms: 100` 快速获得 `execution_id`。需要跨断线继续运行时设置 `execution_mode: "detached"`。用 `terminal_status` 查询，并以 `terminal_signal` 向指定执行发送 `SIGINT`、`SIGTERM` 或 `SIGKILL` |
| 增量读取 | `terminal_read` 传 `session_id`，任务输出另传 `execution_id`。后续请求沿用上一批的 `next_cursor`。`truncated` 表示游标之前的记录已因限额或保留期被清理 |
| 恢复或关闭 | 重连用 `terminal_activate` 或 `terminal_status(reconnect=true)`。`terminal_close(preserve_remote=true)` 断开 SSH 并保留 tmux，`false` 销毁此终端的 tmux。如仍有活跃 detached 任务，先结束该任务 |

完整模式的远端 Linux 需要 `tmux` 和 `python3`（标准库包含 SQLite），用于恢复 Shell 与 detached 日志。设置 `PTMCP_ALLOW_PTY_FALLBACK=true` 可在缺少 tmux 时使用普通 PTY，断线后该 Shell 不可恢复。保留状态只涵盖服务重启和网络断线，远端操作系统重启会清除内存中的 tmux 会话。普通执行断线时可能返回 `UNKNOWN`，应先核对实际状态。输出包含 UTF-8 和原始 ANSI 控制序列，按流返回，属于远端不可信数据。

SSH keepalive 主动检测断线，空闲清理会断开无前台任务的连接。SSH 仅在后续工具调用需要连接时按需重连，同一会话的恢复串行进行。崩溃后可以接管尚未就绪的 tmux 初始化。已经就绪的 Shell 一旦确认丢失，会持久化为不可恢复，需关闭旧终端后显式创建新的终端。

输出按日志分别限制体积。新记录以 UTF-8 边界切分，旧日志中的超大记录会在返回的页面中截断并推进游标。终端服务定期清理本地过期输出，远端日志在访问时检查保留期。多任务合计的磁盘空间及审计日志保留由部署文件系统和日志服务控制。Detached Worker 失去联系且没有可验证的最终结果时返回 `UNKNOWN`。Worker 崩溃可能使自行脱离进程组的后代继续运行。

退出码非零的远端命令仍可返回 `COMPLETED` 和实际 `exit_code`。工具本身的错误使用 MCP `isError` 和结构化 `code`。启动长任务时，`yield_time_ms` 只影响第一次等待时长。执行期限由 `PTMCP_EXECUTION_TIMEOUT` 控制。审计以结构化 JSON 写到服务日志，记录操作与资源标识。

### 接入 Codex 与 Claude Code

远程部署的终端服务可通过 SSH 端口转发访问。保持隧道运行，在启动客户端的环境中设置 `PTMCP_TOKEN`。

```powershell
ssh -i "$env:USERPROFILE\.ssh\terminal_host" -N -L 8766:127.0.0.1:8766 operator@mcp.example.internal
```

Codex 配置：

```toml
[mcp_servers.persistent_terminal]
url = "http://127.0.0.1:8766/mcp"
bearer_token_env_var = "PTMCP_TOKEN"
```

Claude Code 的 `.mcp.json` 示例：

```json
{
  "mcpServers": {
    "persistent-terminal": {
      "type": "http",
      "url": "http://127.0.0.1:8766/mcp",
      "headers": {"Authorization": "Bearer ${PTMCP_TOKEN}"}
    }
  }
}
```

参阅 [Codex MCP](https://developers.openai.com/codex/mcp) 和 [Claude Code MCP](https://code.claude.com/docs/en/mcp)。

### Docker Compose

在 Linux 创建 `terminal-secrets/` 并放入 `known_hosts`、`principals.json`、`credentials.json` 和所需密钥。容器内凭据路径以 `/run/ptmcp/` 开头。容器使用与目录所有者对应的非 root UID/GID，数据在单独的命名卷中。

```bash
export PTMCP_UID="$(id -u)" PTMCP_GID="$(id -g)"
docker compose up -d --build
docker compose ps
```

Compose 仅将宿主机回环端口映射到容器，可通过 SSH 隧道或经过认证的 HTTPS 反向代理访问。日志通过 `docker compose logs` 查询。

基础镜像默认使用 `python:3.12-slim`。如果部署端使用其他容器仓库，可用 `PTMCP_PYTHON_IMAGE` 指定同版本的 Python 镜像。

### 自动化验证

```bash
uv run --locked --extra test pytest -q
docker build -f tests/sshd.Dockerfile -t ssh-mcp-test-sshd:local tests
PTMCP_TEST_SSH_IMAGE=ssh-mcp-test-sshd:local uv run --locked --extra test pytest -q
```

Docker 测试临时启动独立的 OpenSSH 和 tmux，覆盖单连接多 Channel、PTY Shell 状态、进程级信号、输出限额、身份隔离、重启恢复和 detached 退出码。默认测试命令在没有测试镜像变量时跳过 Docker 用例。

在 Ubuntu 上，Python 测试 29 项通过（含 13 个真实 OpenSSH 场景），覆盖网页连接管理和终端故障恢复。Docker Compose 健康检查通过，官方 MCP SDK 成功执行初始化、工具发现和带令牌的调用。原 TypeScript 测试 10 项通过。部署服务使用 SQLite，Python 端只提供 Streamable HTTP。

## 原 TypeScript 服务

一个受策略约束的 SSH MCP Server。它同时支持本地 STDIO 和内网 Streamable HTTP，让 AI 通过系统 OpenSSH 对明确配置的服务器执行预定义只读操作，不接受任意 Shell，也不会读取或返回 SSH 私钥。

## 第一版的安全边界

- 主机只能来自 `config.yaml` 白名单。
- 操作只能来自配置中的固定命令模板，且必须声明为 `readOnly: true`。
- 参数必须占据完整的命令参数，并通过正则表达式校验。
- 远端参数使用 POSIX Shell 单引号转义；禁止 NUL 和换行。
- 强制非交互认证、严格校验 host key、关闭 agent forwarding 和端口转发。
- 输出有大小和时间限制，并被明确标记为不可信远端内容。
- 审计记录不保存参数值或私钥路径。
- `list_agent_keys` 只返回 agent 中密钥的指纹、位数和算法，不返回注释或密钥内容。
- HTTP Token 仅以 SHA-256 哈希保存，每个 Token 可以限制可访问的主机和操作。
- HTTP 模式具有 Host Header 校验、限流、会话数量和空闲时间限制。

本项目的第一版面向 Linux/Unix SSH 目标，因为远端命令采用 POSIX Shell 参数转义。不要把它配置给 Windows SSH 目标。

## 安装与构建

需要 Node.js 20+ 和系统 OpenSSH：

```powershell
npm install
npm run build
Copy-Item config.example.yaml config.yaml
```

编辑 `config.yaml`，至少替换主机地址、用户和 `knownHostsFile`。`config.yaml` 已被 `.gitignore` 忽略。

推荐将带密码的专用密钥加载进 `ssh-agent`，并省略 `identityFile`。如果指定 `identityFile`，它必须是绝对路径，且应位于项目目录之外。

先由人工核对服务器指纹，再把主机密钥加入独立的 `known_hosts` 文件。不要盲目信任未经其他渠道核验的 `ssh-keyscan` 结果。

## 本地 STDIO 模式

```powershell
$env:SSH_MCP_CONFIG = "D:\env\ssh_mcp\config.yaml"
npm start
```

STDIO 是 MCP 协议通道，因此正常运行时不要向 stdout 写日志；启动信息和错误会写到 stderr。

### 连接本地 Codex

构建后，在 Codex 的 `config.toml` 中加入：

```toml
[mcp_servers.local_ssh]
command = "node"
args = ["D:\\env\\ssh_mcp\\dist\\index.js"]
cwd = "D:\\env\\ssh_mcp"
enabled_tools = ["list_hosts", "list_operations", "test_connection", "run_operation", "list_agent_keys"]
default_tools_approval_mode = "prompt"
startup_timeout_sec = 10
tool_timeout_sec = 60

[mcp_servers.local_ssh.env]
SSH_MCP_CONFIG = "D:\\env\\ssh_mcp\\config.yaml"
```

保存后重启对应的 Codex 客户端，再通过 `/mcp` 检查连接状态。官方接入说明见 [OpenAI MCP 文档](https://developers.openai.com/codex/mcp)。

## 内网 HTTP 模式

HTTP 模式提供类似第三方 MCP 服务的统一地址：

```text
http://192.168.1.50:8787/mcp
```

不同 Agent 使用各自的 Bearer Token。私钥和 Token 明文都不会分发到服务端配置文件；服务端 Token 文件只保存不可逆哈希。

### 1. 配置监听地址

在 `config.yaml` 中填写本机固定内网 IP 或内部 DNS 名称：

```yaml
http:
  host: 0.0.0.0
  port: 8787
  allowedHosts: [192.168.1.50, ssh-mcp.lan, localhost]
  tokenStoreFile: .data/tokens.json
  maxRequestsPerMinute: 120
  sessionIdleMinutes: 60
  maxSessions: 100
```

`allowedHosts` 必须包含 Agent 实际用于访问服务的 IP 或主机名，用于防御 Host Header/DNS rebinding 攻击。

### 2. 在服务端生成 Token

生成一个可访问所有已配置主机和操作的 Token：

```powershell
$env:SSH_MCP_CONFIG = "D:\env\ssh_mcp\config.yaml"
npm run token:create -- codex_laptop
```

命令只显示一次 Token，类似：

```text
<your-ssh-mcp-token>
```

推荐为每个 Agent 限制权限：

```powershell
npm run token:create -- monitoring_agent `
  --host production_web `
  --operation uptime `
  --operation service_status
```

查看 Token 元数据（不会显示 Token 或哈希）：

```powershell
npm run token:list
```

撤销 Token，下一次请求立即失效：

```powershell
npm run token:revoke -- monitoring_agent
```

HTTP Token 默认不能调用 `list_agent_keys`。只有明确需要时才在创建命令后增加 `--allow-agent-keys`。

### 3. 启动内网服务

```powershell
$env:SSH_MCP_CONFIG = "D:\env\ssh_mcp\config.yaml"
npm run start:http
```

健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health -Headers @{ Host = "localhost" }
```

### 4. Agent 接入

Codex 的远程 MCP 配置：

```toml
[mcp_servers.ssh_gateway]
url = "http://192.168.1.50:8787/mcp"
bearer_token_env_var = "SSH_MCP_TOKEN"
default_tools_approval_mode = "prompt"
```

在运行 Agent 的机器上设置：

```powershell
$env:SSH_MCP_TOKEN = "<your-ssh-mcp-token>"
```

其他支持 Streamable HTTP MCP 和 Bearer Token 的 Agent 使用相同 URL 和 Token 即可。

### 内网传输安全

普通 HTTP 会让 Bearer Token 以明文形式经过局域网。只应在可信、隔离的内网或加密 VPN（例如 Tailnet）中使用。对于共享 Wi-Fi、办公访客网络或不完全可信的局域网，应在前面配置 HTTPS 反向代理；不要直接把 8787 端口映射到公网。

## SSH 密钥管理

HTTP 服务可以同时启动独立的管理页面。把下面的配置加入 `config.yaml`，在配置目录生成管理员令牌，再启动或重启 HTTP 服务。

```yaml
keys:
  directory: .data/keys
admin:
  port: 8788
  tokenFile: .data/admin-token
```

```bash
umask 077
mkdir -p .data
(set -o noclobber; openssl rand -hex 32 > .data/admin-token)
```

管理端固定监听回环地址。远程部署时，先从客户端通过 SSH 转发管理端口。用浏览器打开 `http://127.0.0.1:8788/`，输入服务端 `.data/admin-token` 中的管理令牌。

```bash
ssh -N -L 8788:127.0.0.1:8788 user@ssh-mcp-server
```

页面支持粘贴或选择 OpenSSH 公钥文件、导入无口令 SSH 私钥、查看指纹、复制公钥和移除条目。私钥导入支持 POSIX 部署，依赖系统 `ssh-keygen`。私钥文件保存在服务账号可读的 `0600` 文件中，页面只返回公钥和元数据。

使用「生成密钥」可以在密钥库里创建 Ed25519、RSA 3072/4096 或 ECDSA P-256 密钥。生成的私钥无口令，保存在部署服务器上供非交互 SSH 使用。

在任意密钥的条目上选择「安装公钥」，选取已配置主机或手填地址、用户和端口，然后生成并复制安装命令。命令需在已有权限登录目标账号的终端执行，目标 Linux 服务器需提供 `flock`。命令只传输公钥，追加到目标账号的 `~/.ssh/authorized_keys`，重复执行时保留原有条目和选项。若需要删除服务器上已安装的公钥，在目标账号的 `authorized_keys` 中移除对应条目。

要让某台主机使用已导入的私钥，在该主机下设置 `identityKey: 密钥ID`，然后重启服务。配置中的 `identityFile` 和 `identityKey` 二选一。管理页面会显示引用该密钥的主机，并阻止删除正在被引用的条目。

## 暴露的工具

- `list_hosts`：列出启用的主机别名，不暴露私钥路径。
- `list_operations(host_id)`：列出某台主机允许的操作和参数说明。
- `test_connection(host_id)`：测试严格 host key 校验及非交互密钥认证。
- `run_operation(host_id, operation_id, parameters)`：执行预定义只读操作。
- `list_agent_keys`：列出本机 `ssh-agent` 中的公钥指纹元数据；HTTP Token 默认无权使用。

## 开发验证

```powershell
npm run check
npm test
```

测试使用模拟 SSH 进程，不会连接真实服务器。

## 已知限制

- 配置文件属于可信管理面：维护者必须确认配置的命令确实只读。
- 当前没有上传、下载、任意命令、SSH 密钥生成/删除或 sudo 操作。
- MCP 无法约束 AI 客户端自身已有的本机文件或 Shell 权限；私钥仍需依靠系统 ACL、客户端沙箱和远端最小权限共同保护。
