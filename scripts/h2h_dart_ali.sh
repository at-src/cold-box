#!/usr/bin/env bash
set -euo pipefail
ROOT="/opt/ref/agentic-dart"
source /opt/postmortem/bin/load-agent-env
export DART_MODEL="${ANTHROPIC_MODEL:-claude-sonnet-4-6}"
export PYTHONPATH="${ROOT}/dart_mcp/src:${ROOT}/dart_audit/src:${ROOT}/dart_agent/src:${ROOT}/dart_corr/src"
export DART_EVIDENCE_ROOT="${HOME}/cases/ali-hadi-1/extracted"
mkdir -p /tmp/llm-h2h
cd "$ROOT"
python3 -m dart_agent --mode live \
  --case h2h-dart-ali \
  --out /tmp/llm-h2h/dart-ali \
  --model "$DART_MODEL" \
  --max-iterations 25 \
  --prompt "Investigate Windows XAMPP web server compromise. Check web/logs/access.log, web/var/www/html/uploads/, logs/Security.evtx, memdump/ memory. Use MCP tools. End with REPORT: JSON."
