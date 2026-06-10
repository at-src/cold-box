#!/usr/bin/env bash
set -euo pipefail
cd /opt/postmortem
source bin/load-agent-env
EVIDENCE_ROOT=/evidence cold-box-agent run \
  --case-id h2h-cb-ali \
  --evidence-case ali-hadi-1 \
  --from-cache "${HOME}/cases/ali-hadi-1/cache" \
  --extracted-root "${HOME}/cases/ali-hadi-1/extracted" \
  --llm --max-iterations 25
