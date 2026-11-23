#!/usr/bin/env bash
set -euo pipefail
project_dir="${SSH_MCP_DIR:-$HOME/ssh-mcp}"
unit_dir="$HOME/.config/systemd/user"
unit=ssh-mcp.service
export PATH="$HOME/.local/bin:$PATH"

case "${1:-}" in
  install)
    cd "$project_dir"
    npm ci
    npm run build
    mkdir -p "$unit_dir"
    node_path="$(command -v node)"
    cat > "$unit_dir/$unit" <<EOF
[Unit]
Description=SSH MCP server
After=network-online.target

[Service]
WorkingDirectory=$project_dir
Environment=SSH_MCP_CONFIG=$project_dir/config.yaml
ExecStart=$node_path $project_dir/dist/http.js
Restart=on-failure
RestartSec=3
UMask=0077

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable --now "$unit"
    ;;
  start|stop|restart|status) systemctl --user "$1" "$unit" ;;
  update)
    cd "$project_dir"
    npm ci
    npm run build
    systemctl --user restart "$unit"
    ;;
  logs) journalctl --user -u "$unit" -f ;;
  *) echo "Usage: $0 {install|start|stop|restart|status|update|logs}" >&2; exit 2 ;;
esac
