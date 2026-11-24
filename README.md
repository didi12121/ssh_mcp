# SSH MCP

通过 MCP 管理 SSH 服务器、使用持久终端和执行远程命令。网页管理端用于管理 SSH 密钥、连接和 Token。MCP 客户端按 Token 授权访问指定服务器。

- 交互式 Shell 通过 tmux 保留工作目录、环境变量和会话状态。
- 独立命令使用单独的 SSH Channel，可与交互式 Shell 并行执行。长任务可在 SSH 断开后继续运行。
- Token 按连接、工作区和执行权限授权，可设置有效期、撤销和轮换。

| 服务 | 默认入口 | 用途 |
| --- | --- | --- |
| 持久终端 MCP | `http://127.0.0.1:8766/mcp` | 连接客户端、管理终端和执行任务 |
| 网页管理端 | `http://127.0.0.1:8788/` | 管理密钥、SSH 连接和 MCP Token |
| 只读 SSH MCP | `http://127.0.0.1:8787/mcp` | 执行 `config.yaml` 定义的只读操作，支持 HTTP 与 STDIO |

## 安装与启动

在运行服务的 Linux 机器上准备 Python 3.12+、uv、Node.js 20+、npm、OpenSSH、OpenSSL 和用户级 systemd。

```bash
git clone https://github.com/didi12121/ssh_mcp.git ~/ssh-mcp
cd ~/ssh-mcp

cp .env.example .env
cp config.example.yaml config.yaml
install -d -m 700 .data .data/keys .data/terminal
touch .data/terminal/known_hosts
(umask 077; set -o noclobber; openssl rand -hex 32 > .data/admin-token)
```

在 `.env` 中设置以下两项，两个服务使用同一个管理员令牌文件和密钥目录。

```dotenv
PTMCP_WEB_ADMIN_TOKEN_FILE=.data/admin-token
PTMCP_MANAGED_KEYS_DIR=.data/keys
```

编辑 `config.yaml` 下的对应字段，保留示例文件中的其他配置。示例 `hosts` 和 `operations` 用于只读 SSH 服务，持久终端的连接在网页内单独管理。

```yaml
ssh:
  knownHostsFile: .data/terminal/known_hosts

keys:
  directory: .data/keys

admin:
  port: 8788
  tokenFile: .data/admin-token
  terminalAdminPort: 8766

http:
  host: 127.0.0.1
  port: 8787
  allowedHosts: [127.0.0.1, localhost]
```

安装并启动服务，在服务端检查状态。

```bash
bash deploy-terminal.sh install
bash deploy-user.sh install

systemctl --user is-active persistent-terminal-mcp ssh-mcp
curl -fsS http://127.0.0.1:8766/health
curl -fsS http://127.0.0.1:8787/health
```

开发时可在两个终端分别前台启动 `uv run --locked terminal-mcp serve` 和 `npm ci && npm run build && npm run start:http`。

## 添加 SSH 连接

### 1. 打开管理页并安装登录公钥

在客户端建立 SSH 隧道。下面同时转发管理页和持久终端 MCP。

```bash
ssh -N -L 127.0.0.1:8788:127.0.0.1:8788 -L 127.0.0.1:8766:127.0.0.1:8766 operator@mcp.example.internal
```

打开 [SSH 管理页](http://127.0.0.1:8788/)，用服务端 `.data/admin-token` 中的令牌登录。在「密钥库」生成或导入 SSH 私钥。点击该密钥的「安装公钥」，填写目标地址、SSH 用户和端口，然后在已有权登录目标账号的终端执行生成的命令。该命令需要目标服务器提供 `flock`。

### 2. 核对并登记主机指纹

| 文件 | 位置 | 作用 |
| --- | --- | --- |
| `~/.ssh/authorized_keys` | 目标服务器的登录账号 | 授予对应私钥的登录权限 |
| `known_hosts` | MCP 服务端，由 `PTMCP_KNOWN_HOSTS` 指定 | 验证目标服务器身份 |

从目标服务器的控制台、已信任的终端或管理员处取得可信指纹。若服务器使用 ED25519 主机密钥，可在目标端用下面的命令查看。

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

在 **MCP 服务所在机器**进入 Python 服务的工作目录，替换以下示例地址、端口和可信指纹，再执行。地址和端口与页面中的连接配置保持一致。

```bash
(
  set -eu
  umask 077
  ssh_target='server.example.internal'
  ssh_port=22
  trusted_fingerprint='SHA256:此处替换为已核对的指纹'
  known_hosts="$(.venv/bin/python -c 'from persistent_terminal_mcp.config import Settings; print(Settings().known_hosts.resolve())')"
  lookup="$ssh_target"
  if [ "$ssh_port" -ne 22 ]; then lookup="[$ssh_target]:$ssh_port"; fi

  candidate="$(ssh-keyscan -T 5 -p "$ssh_port" -t ed25519 "$ssh_target" 2>/dev/null)"
  scanned_fingerprint="$(printf '%s\n' "$candidate" | ssh-keygen -lf - | awk '{print $2}')"
  if [ "$scanned_fingerprint" != "$trusted_fingerprint" ]; then
    printf '%s\n' '指纹不匹配或返回了多个指纹，已停止登记。' >&2
    exit 1
  fi

  mkdir -p "$(dirname "$known_hosts")"
  touch "$known_hosts"
  if ssh-keygen -F "$lookup" -f "$known_hosts" >/dev/null; then
    printf '%s\n' '已有记录，请核对现有指纹。'
    ssh-keygen -F "$lookup" -f "$known_hosts" | ssh-keygen -lf -
  else
    printf '\n%s\n' "$candidate" >> "$known_hosts"
  fi
)
```

在「SSH 连接」中保存连接并点「测试连接」。同一地址和端口可以复用已登记的主机密钥。若指纹后来发生变化，先通过可信渠道确认原因，再备份并更新该地址和端口的记录。若目标使用其他类型的主机密钥，请向管理员取得对应公钥及指纹。

### 3. 安装持久终端依赖

使用持久终端时，在**目标服务器**用 `cat /etc/os-release` 查看发行版，并选择对应命令。以 root 登录时去掉 `sudo`。

Ubuntu / Debian

```bash
sudo apt update
sudo apt install tmux python3
```

Fedora

```bash
sudo dnf install tmux python3
```

用连接配置中的 SSH 用户验证 `tmux -V` 和 `python3 -c 'import sqlite3'`。如果系统已安装 `tmux` 但网页测试无法检测到，请检查该账号的非交互 SSH 会话中的 `PATH`。[tmux 官方安装指南](https://github.com/tmux/tmux/wiki/Installing)

## 接入 MCP 客户端

在管理页打开「MCP Token」，创建 Token 并勾选允许访问的 SSH 连接、工作区及执行权限。复制一次性显示的 Token。使用前面的隧道将持久终端 MCP 地址设为 `http://127.0.0.1:8766/mcp`，客户端通过 `Authorization: Bearer <MCP Token>` 认证。

### Codex

在启动 Codex 的环境中设置 `PTMCP_TOKEN`，然后注册服务。PowerShell 示例：

```powershell
$env:PTMCP_TOKEN = [System.Net.NetworkCredential]::new(
  "", (Read-Host "粘贴 MCP Token" -AsSecureString)
).Password
codex mcp add ssh_mcp --url http://127.0.0.1:8766/mcp --bearer-token-env-var PTMCP_TOKEN
```

也可以在 Codex 的用户配置文件 `~/.codex/config.toml` 中填入：

```toml
[mcp_servers.ssh_mcp]
url = "http://127.0.0.1:8766/mcp"
bearer_token_env_var = "PTMCP_TOKEN"
```

启动客户端后，让 Codex 调用 `connection_list` 列出获准访问的服务器。[Codex MCP 文档](https://developers.openai.com/codex/mcp)

### Claude Code

在 Claude Code 启动环境中设置 `PTMCP_TOKEN`，然后在项目的 `.mcp.json` 中配置：

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "type": "http",
      "url": "http://127.0.0.1:8766/mcp",
      "headers": { "Authorization": "Bearer ${PTMCP_TOKEN}" }
    }
  }
}
```

[Claude Code MCP 文档](https://code.claude.com/docs/en/mcp)

## 终端与任务

| 操作 | MCP 工具 |
| --- | --- |
| 查找获准访问的服务器 | `connection_list` |
| 创建、查找或切换终端 | `terminal_create`、`terminal_list`、`terminal_activate` |
| 向持久 Shell 输入文本 | `terminal_send` |
| 在独立 Channel 执行命令 | `terminal_exec`，用 `operation` 调用预定义命令，或用 `command` 提交获准的自定义命令 |
| 提交可跨 SSH 断线继续运行的任务 | `terminal_exec`，设置 `execution_mode: "detached"` |
| 查看状态与增量输出 | `terminal_status`、`terminal_read`。从返回的 `next_cursor` 继续读取 |
| 中断、调整大小、关闭 | `terminal_signal`、`terminal_resize`、`terminal_close` |

`yield_time_ms` 控制首次等待时长。命令还在执行时，用返回的 `execution_id` 查询状态和读取输出。`terminal_close` 默认保留远端 tmux。需要清理时，传入 `preserve_remote: false`。

## 部署选项

### 局域网 HTTPS 管理页

在 `config.yaml` 的 `admin` 下添加：

```yaml
  lan:
    address: 192.168.1.50
    subnet: 192.168.1.0/24
    certFile: .data/admin-lan.crt
    keyFile: .data/admin-lan.key
```

将地址、网段和证书路径换成实际值。证书的 SAN 必须包含管理页的 IPv4 地址。TLS 私钥由服务账号持有，权限为 `0600`。`lan.port` 省略时使用 `admin.port`，在局域网 IP 上单独绑定。

重启 SSH 管理服务后，从允许的网段打开 `https://192.168.1.50:8788/`，继续使用管理令牌登录。自签证书需通过可信渠道核对并在客户端信任。远程 MCP 客户端可继续用 SSH 隧道访问 `8766`。

### Docker Compose

Compose 提供 Python 持久终端 MCP。准备 `terminal-secrets/`，放入 `known_hosts`、所需的 `credentials.json` 和密钥。容器内凭据文件引用路径以 `/run/ptmcp/` 开头。

```bash
export PTMCP_UID="$(id -u)" PTMCP_GID="$(id -g)"
docker compose up -d --build
docker compose ps
```

服务使用非 root 用户运行，数据保存在命名卷中。宿主机默认在回环地址发布 MCP 端口。联合部署网页管理端时，管理代理与 Python 服务须共享回环网络。

### 只读 SSH MCP

配置 `config.yaml` 的 `hosts` 和 `operations`，并在 `ssh.knownHostsFile` 指定已核验的主机密钥文件。对带参数的命令，使用独立占位参数及对应的正则规则。只读范围由管理员配置的命令以及远端账号权限共同决定。

```bash
npm run build
npm run token:create -- monitoring --host production_web --operation uptime
npm run start:http
```

HTTP 客户端连接 `http://127.0.0.1:8787/mcp` 并携带签发的 Token。用 `npm run token:list` 查看 Token，用 `npm run token:revoke -- monitoring` 撤销。使用 STDIO 时，以 MCP 客户端启动 `node /path/to/ssh-mcp/dist/index.js`，设置 `SSH_MCP_CONFIG` 为 `config.yaml` 的绝对路径。

## 运维与验证

```bash
bash deploy-terminal.sh status
bash deploy-user.sh status
journalctl --user -u persistent-terminal-mcp -u ssh-mcp
```

更新前保留 `.env`、`config.yaml`、SQLite 数据库和 `.data/` 下的密钥、令牌与主机指纹。等待前台执行结束后，按需运行 `bash deploy-terminal.sh update` 和 `bash deploy-user.sh update`，再检查健康接口和管理页。

```bash
npm test
uv run --locked --extra test pytest -q
docker build -f tests/sshd.Dockerfile -t ssh-mcp-test-sshd:local tests
PTMCP_TEST_SSH_IMAGE=ssh-mcp-test-sshd:local uv run --locked --extra test pytest -q
```

浏览器测试需要 Node.js 22+ 和 Chrome。运行 `npm run build` 后，将 `PTMCP_TEST_PYTHON` 设为项目虚拟环境的 Python 路径，将 `PTMCP_TEST_CHROME` 设为 Chrome 路径，再执行 `node tests/browser_identity.mjs`。

- 终端操作同时检查 Token 的连接授权、工作区权限和会话所有权。Token 轮换保留会话归属。取消连接授权会阻止后续操作，已经开始的远端任务可继续运行。
- 修改服务器地址、端口、账号或凭据会使该连接的 Token 授权失效。重新授权后创建新终端，相关历史终端可由管理员清理。
- 普通前台任务随 SSH Channel 断开时可能丢失。状态为 `UNKNOWN` 的任务需要先核实结果。持久 Shell 和 detached 任务依赖目标端的 tmux 状态。
- 完整 Shell 可读取其远端账号有权访问的信息。对不同信任范围的 Agent，使用独立且受限的 SSH 账号。管理员令牌、MCP Token、私钥及运行数据应保存在部署环境中。
