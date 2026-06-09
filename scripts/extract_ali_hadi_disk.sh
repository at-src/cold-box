#!/usr/bin/env bash
# Extract key disk artifacts from Ali Hadi Case1-Webserver.E01 into CASE_OUTPUT.
# Read-only on /evidence; writes under ${CASE_OUTPUT:-$HOME/cases}/ali-hadi-1/extracted/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE="${EVIDENCE_ROOT:-/evidence}"
E01="$EVIDENCE/ali-hadi-1/Case1-Webserver.E01"
CASE_OUT="${CASE_OUTPUT:-$HOME/cases}"
OUT="$CASE_OUT/ali-hadi-1/extracted"
MOUNT="${ALI_HADI_MOUNT:-/tmp/ali-hadi-mount}"
PART_OFFSET=2048

if [[ ! -f "$E01" ]]; then
  echo "Missing $E01 — set EVIDENCE_ROOT if cases live elsewhere." >&2
  exit 1
fi

mkdir -p "$OUT/logs" "$MOUNT"

if [[ ! -f "$MOUNT/ewf1" ]]; then
  echo "Mounting $E01 at $MOUNT ..."
  ewfmount "$E01" "$MOUNT"
fi

IMG="$MOUNT/ewf1"

echo "Extracting \$MFT (inode 0) ..."
icat -o "$PART_OFFSET" "$IMG" 0 > "$OUT/\$MFT"

echo "Extracting Security.evtx and System.evtx ..."
icat -o "$PART_OFFSET" "$IMG" 42093 > "$OUT/logs/Security.evtx"
icat -o "$PART_OFFSET" "$IMG" 42091 > "$OUT/logs/System.evtx"

# Win Server 2008 image: no Amcache.hve (Win8+) and no Prefetch directory in this image.
# Disk tools that need prefetch/amcache use bundled cold-box-lab for CI; real case uses MFT + EVTX + memory.

echo "Done. Extracted:"
ls -lh "$OUT/\$MFT" "$OUT/logs/"*.evtx
