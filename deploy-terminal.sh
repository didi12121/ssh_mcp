#!/usr/bin/env bash
set -euo pipefail
umask 077
project="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
unit=persistent-terminal-mcp.service
unit_dir="$HOME/.config/systemd/user"
export PATH="$HOME/.local/bin:$PATH"

escape_unit() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/%/%%/g'; }
[[ "$project" != *$'\n'* && "$project" != *$'\r'* ]] || { echo 'Unexpected newline in project path' >&2; exit 1; }

case "${1:-}" in
  install|update)
    cd "$project"
    if [[ ! -e .env ]]; then
      cp .env.example .env
    fi
    mkdir -p .data
    exec 9>.data/terminal-upgrade.lock
    flock -n 9
    if systemctl --user is-active --quiet "$unit"; then
      PYTHONPATH="$project/src" .venv/bin/python -m persistent_terminal_mcp.main preflight
      directory="$(mktemp -d .data/terminal-config-before-upgrade.XXXXXX)"
      cp -p .env "$directory/.env"
      systemctl --user stop "$unit"
    fi
    uv sync --locked --no-dev --no-editable --reinstall-package persistent-terminal-mcp
    .venv/bin/terminal-mcp migrate
    if [[ "$1" == install ]]; then
      mkdir -p "$unit_dir"
      cat > "$unit_dir/$unit" <<EOF
[Unit]
Description=Persistent Terminal MCP Server
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${project//%/%%}
ExecStart=:"$(escape_unit "$project/.venv/bin/terminal-mcp")" serve
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=default.target
EOF
      systemd-analyze --user verify "$unit_dir/$unit"
      systemctl --user daemon-reload
      systemctl --user enable "$unit"
    fi
    systemctl --user start "$unit"
    ;;
  start|stop|restart|status)
    systemctl --user "$1" "$unit"
    ;;
  logs)
    journalctl --user -u "$unit" -f
    ;;
  *)
    echo "Usage: $0 {install|start|stop|restart|status|update|logs}" >&2
    exit 2
    ;;
esac
