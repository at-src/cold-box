#!/usr/bin/env bash
# One-time Claude Code + cold-box-room parallel track setup (does not start a session).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
VENV="$REPO_ROOT/.venv"
export PATH="$HOME/.local/bin:$VENV/bin:$PATH"

echo "==> cold-box-room Claude Code setup"
echo "    project: $ROOT"
echo "    venv:    $VENV"

if ! command -v claude >/dev/null 2>&1; then
  echo "==> Installing Claude Code (native)..."
  curl -fsSL https://claude.ai/install.sh | bash
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "==> Claude Code: $(claude --version)"

if [[ ! -x "$VENV/bin/python" ]]; then
  echo "ERROR: missing venv at $VENV — create with: python3 -m venv $VENV" >&2
  exit 1
fi

echo "==> Installing cold-box-room into venv (mcp extra)..."
"$VENV/bin/pip" install -q -e "$ROOT[dev,mcp]"

echo "==> Verifying MCP entrypoint..."
test -x "$VENV/bin/cold-box-room-mcp"

echo "==> Verifying MCP config..."
test -f "$ROOT/.mcp.json"
test -f "$ROOT/.claude/settings.json"

if ! grep -q 'HOME/.local/bin' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  echo "==> Added ~/.local/bin to ~/.bashrc"
fi

chmod +x "$ROOT/bin/claude-room" "$ROOT/scripts/monitor_case.sh" "$ROOT/.claude/hooks/log-mcp-tool.sh"

echo ""
echo "Setup complete. Do NOT start Claude Code until intake is done."
echo ""
echo "  1. Intake (terminal):"
echo "       cd $ROOT"
echo "       source $VENV/bin/activate"
echo "       cold-box-room intake --case-id CASE --source /evidence/... --link"
echo "       cold-box-room r1-check --case-id CASE --promote"
echo ""
echo "  2. Monitor (second terminal):"
echo "       $ROOT/scripts/monitor_case.sh CASE"
echo ""
echo "  3. When ready to investigate:"
echo "       $ROOT/bin/claude-room"
echo "       Paste prompt from docs/CLAUDE_CODE_START_PROMPT.md"
echo ""
echo "  Check MCP without a session:"
echo "       cd $ROOT && claude mcp list"
