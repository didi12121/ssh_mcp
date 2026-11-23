#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
service_name="ssh-mcp.service"
unit_file="/etc/systemd/system/$service_name"
service_user="${SSH_MCP_USER:-$(stat -c '%U' "$project_dir")}"
config_file="${SSH_MCP_CONFIG:-$project_dir/config.yaml}"

case "${1:-}" in
  install)
    [[ $EUID -eq 0 ]] || { echo 'Run install as root, setting SSH_MCP_USER if needed.' >&2; exit 1; }
    [[ "$project_dir$config_file" != *$'\n'* ]] || { echo 'Paths must not contain newlines.' >&2; exit 1; }
    [[ -f "$config_file" ]] || { echo "Config not found: $config_file" >&2; exit 1; }
    id "$service_user" >/dev/null
    node_path="$(command -v node)"
    (cd "$project_dir" && npm ci && npm run build)
    escape_unit() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g'; }
    cat > "$unit_file" <<EOF
[Unit]
Description=Local SSH MCP
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$service_user
WorkingDirectory="$(escape_unit "$project_dir")"
Environment="SSH_MCP_CONFIG=$(escape_unit "$config_file")"
ExecStart="$(escape_unit "$node_path")" "$(escape_unit "$project_dir/dist/http.js")"
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now "$service_name"
    ;;
  start|stop|restart|status)
    systemctl "$1" "$service_name"
    ;;
  update)
    (cd "$project_dir" && npm ci && npm run build)
    systemctl restart "$service_name"
    ;;
  logs)
    journalctl -u "$service_name" -f
    ;;
  *)
    echo "Usage: $0 {install|start|stop|restart|status|update|logs}" >&2
    exit 2
    ;;
esac
