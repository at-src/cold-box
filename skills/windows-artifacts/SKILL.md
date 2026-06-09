# Disk artifact parsing

Use this after disk files are extracted into the case folder under `EVIDENCE_ROOT`. cold-box reads artifacts; it does not mount E01 images inside the evidence tree.

## Tools you have

| Tool | Input | Output use |
|------|-------|------------|
| `disk_parse_prefetch` | `.pf` file (falls back to sibling `.json` if parse fails) | Execution history, referenced binary name |
| `disk_parse_amcache` | `Amcache.hve` | Programs that ran, paths, hashes |
| `disk_parse_evtx` | `.evtx` log | Structured events (R3 later) |
| `disk_parse_mft` | `$MFT` or CSV export | File metadata rows |
| `disk_detect_timestomp` | `$MFT` or `$MFT.csv` | Rows where $SI and $FN timestamps disagree |

Backend binaries are overridable: `PREFETCH_PARSER`, `AMCACHE_PARSER`, `EVTX_ECMD`, `MFTECMD`.

Each run is audited. Copy the returned `audit_id` into findings.

## What the verifier expects

**R2 — no execution trail.** You saw a process in memory (`mem_pslist`) but neither prefetch nor amcache mentions that executable basename. That gap is suspicious for user-started programs (we skip core system images like `smss.exe`).

**R4 — timestomp.** In MFT output, compare `Created0x10` (standard information) with `Created0x30` (file name). If standard-info creation is *earlier* than file-name creation by more than a second, someone likely backdated the file (MITRE T1070.006). `disk_detect_timestomp` encodes that check; large deltas on `.exe` files deserve priority.

**R5 — ghost binary.** Prefetch says an executable ran, but no file with that basename exists anywhere under the evidence tree (match is case-insensitive). Our lab case deliberately includes `STAGE-RUNNER.EXE` in prefetch with no matching file — that is the R5 demo IOC.

## Suggested order

1. `evidence_manifest` on the case root.
2. Prefetch under `Windows/Prefetch/`.
3. Amcache if the hive was collected.
4. MFT or `$MFT.csv` for timeline and timestomp.
5. EVTX when you need logons or process creation events.

Cross-check disk results against memory: a binary in prefetch should usually exist on disk unless R5 applies; a process in RAM without disk trail triggers R2.

## Lab case paths

Bundled synthetic disk data lives in `examples/sample-evidence/disk/`:

- `$MFT.csv` — includes timestomp on `stage-dropper.exe`
- Prefetch sidecars for `COLDLOADER.EXE` and ghost `STAGE-RUNNER.EXE`
- `Users/operator/Downloads/coldloader.exe` — on-disk decoy

See `examples/sample-evidence/CASE.md` for the full story.

## Hard rules

Same as memory: read-only evidence, audited writes only, no finding without `audit_ids[]`.
