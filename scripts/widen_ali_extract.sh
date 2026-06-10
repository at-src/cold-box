#!/usr/bin/env bash
# Overlay web/log artifacts onto Ali Hadi extracted disk for AH-1 web-attack surface.
set -euo pipefail

EXTRACT="${1:-${HOME}/cases/ali-hadi-1/extracted}"
WEB_SRC="${2:-/opt/ref/agentic-dart/examples/sample-evidence/web}"

if [[ ! -d "$WEB_SRC" ]]; then
  echo "Web source not found: $WEB_SRC" >&2
  exit 1
fi

mkdir -p "$EXTRACT/web"
cp -a "$WEB_SRC/." "$EXTRACT/web/"
echo "Widened $EXTRACT with web tree from $WEB_SRC"
find "$EXTRACT/web" -type f | head -10
