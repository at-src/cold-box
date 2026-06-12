#!/usr/bin/env bash
# Wire cold-box for Claude Code (2026 MCP project scope).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== cold-box Claude Code setup =="
echo "Repo: $ROOT"

chmod +x "$ROOT/bin/cold-box-mcp-stdio"

if [[ ! -d "$ROOT/.venv" ]]; then
  echo "Creating venv..."
  python3 -m venv "$ROOT/.venv"
fi
# shellcheck disable=SC1091
source "$ROOT/.venv/bin/activate"
pip install -q -e ".[dev]"

echo "Checking MCP server starts..."
timeout 2 "$ROOT/bin/cold-box-mcp-stdio" </dev/null >/dev/null 2>&1 || true

if command -v claude >/dev/null 2>&1; then
  echo "Claude Code CLI found."
  echo "  Project MCP config: $ROOT/.mcp.json"
  echo "  Run: claude   (then /mcp to approve cold-box)"
  claude mcp list 2>/dev/null || true
else
  echo "Claude Code CLI not installed on this machine."
  echo "  Install from: https://code.claude.com/docs/en/quickstart"
  echo "  Project MCP config is ready at: $ROOT/.mcp.json"
fi

cat <<EOF

Next steps:
  export EVIDENCE_ROOT=\${EVIDENCE_ROOT:-/evidence}
  export CASE_OUTPUT=\${CASE_OUTPUT:-/cases}
  cd "$ROOT" && claude

Read: docs/CLAUDE-CODE.md and CLAUDE.md
EOF
