# Ali Hadi Case #1 — cold-box hero case

Real public DFIR scenario: Windows Server 2008 web-server breach with **disk E01 + memory dump from the same host**.

Evidence stays read-only under `EVIDENCE_ROOT` (default `/evidence/ali-hadi-1/`). Extracted artifacts and run output go to `CASE_OUTPUT` (default `/cases` or `$HOME/cases` on this VM).

## Layout

```text
/evidence/ali-hadi-1/
  Case1-Webserver.E01
  memdump/memdump.mem

${CASE_OUTPUT}/ali-hadi-1/
  extracted/
    $MFT
    logs/Security.evtx
    logs/System.evtx
  cache/              ← Vol3 JSON snapshots (demo replay)
  audit.jsonl         ← agent run output
```

## Day 1 — disk extraction

```bash
export EVIDENCE_ROOT=/evidence
export CASE_OUTPUT=/cases   # or $HOME/cases if /cases is not writable

bash scripts/extract_ali_hadi_disk.sh
```

Uses `ewfmount` + `icat` (TSK). NTFS partition offset **2048** sectors.

**Note:** This Win2008 image has **no Amcache.hve** (Amcache is Windows 8+) and **no Prefetch directory** in the filesystem. R2/R5 disk correlation on this case relies on memory + MFT + EVTX; bundled `examples/sample-evidence/` covers prefetch/amcache rules in CI.

## Memory cache (slow once, fast demo)

```bash
export EVIDENCE_ROOT=/evidence CASE_OUTPUT=/cases VOL3=/opt/postmortem/bin/vol
bash scripts/cache_ali_hadi_memory.sh
```

Each Vol call can take ~1–2 minutes on the real `.mem`. Cached JSON under `cache/` is for reproducible demo replay; a full live run is still logged to `audit.jsonl`.

## Smoke-test disk tools on extracted artifacts

```bash
export EVIDENCE_ROOT=/evidence CASE_OUTPUT=/cases

cold-box-mcp  # or invoke tools via Python/agent

# Point disk tools at extracted paths relative to a synthetic case dir, or symlink:
# ln -sfn $CASE_OUTPUT/ali-hadi-1/extracted /cases/ali-hadi-1-disk
```

## Ground truth

Published task list: `/evidence/ground-truth/ali-hadi-dfir.html` (not committed). Agent accuracy scoring (Day 4) maps findings to those tasks.
