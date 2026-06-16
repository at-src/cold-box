# Accuracy report

Measured autonomous hallway performance against keyword benchmarks in `cold_box_room/e2e/benchmarks/`.

---

## Methodology

1. **Corpus** — Layer 1/2 analyst logs, plans, audit stdout (`e2e/accuracy.py`)
2. **Keyword checks** — required vs optional pattern pools per benchmark
3. **Metrics** — recall, precision, F1 per pool
4. **Staging scope** — `required_staging_files` validated against `manifest.json`
5. **Usage** — token counts from `AGENT_RUN.jsonl`

Reproduce any score:

```bash
cd cold-box-room
python scripts/score_e2e_accuracy.py --case-id CASE_ID --benchmark BENCHMARK_ID
```

---

## Terry USB holdout — `terry-fresh-20260615-0345`

**Benchmark:** `terry_usb` · **Model:** claude-sonnet-4-6 · **Hallway:** complete

| Metric | Result |
|--------|--------|
| Required recall | **100%** (4/4) |
| Optional recall | **100%** (2/2) |
| Combined accuracy | **100%** |
| Precision | **100%** |
| Wall time | 16.0 min |
| Assistant turns | 89 |
| Layer 1 / 2 self-score | 9 / 9 |

### Checks hit

| Check | Result |
|-------|--------|
| EWF/E01 format | ✅ |
| FAT32 filesystem | ✅ |
| TERRYS WORK volume label | ✅ |
| Keylogger / R54402.EXE | ✅ |
| Image MD5 | ✅ |
| Partition offset 63 | ✅ |

Unseen holdout image — not used in prompt tuning.

---

## NIST CFReDS Data Leakage PC — `cfreds-leakage`

**Benchmark:** `ndlc_leakage_pc` · **Model:** claude-sonnet-4-6 · **Track:** Claude Code interactive · **Hallway:** complete

| Metric | Result |
|--------|--------|
| Required recall | **100%** (4/4) |
| Optional recall | **100%** (1/1 in-scope) |
| Combined accuracy | **100%** |
| Layer 1 plan score | **100%** (12/12 passed) |
| Successful extractions | **32** |
| Layer 1 / 2 self-score | 9 / 9 |
| Wall time | ~27 min |
| Self-correction events | 1 (fcat → ifind → icat) |

> The Eastern timezone optional check requires `cfreds_2015_data_leakage_rm#1.E01` (removable media image). That image was not in scope for this PC-only run — the check is N/A, not a miss.

### Checks

| Check | Result |
|-------|--------|
| Suspect host / user | ✅ (admin11, SID confirmed) |
| Windows 7 | ✅ (ewfinfo: "Windows 7", SOFTWARE hive) |
| NTFS partitions | ✅ (mmls: offset 206848, fsstat: NTFS) |
| Data leakage scenario | ✅ (Recycle Bin batch deletion, USB artifacts, browser rules out web exfil) |
| PC image MD5 | ✅ (`a49d1254c873808c58e6f1bcd60b5bde`) |
| Eastern timezone | N/A (rm# image not staged) |

### Self-correction documented in audit trail

`CB-541b86fa41d7` (fcat exit 1) → `CB-70493459ba6a` (ifind exit 0, inode 58912) → `CB-62ec250cd23c` (icat exit 0, SYSTEM hive extracted). No human intervention. Full trace: `docs/submission-logs/audit.sample.jsonl`.

---

## Evidence integrity in scoring

| Property | Enforced |
|----------|----------|
| R1 originals sealed | ✅ |
| Tool inputs from sandbox copy | ✅ |
| Manifest scope validated | ✅ |
| Findings → audit_id trace | ✅ |

---

## Benchmark files

| ID | File |
|----|------|
| `terry_usb` | `cold_box_room/e2e/benchmarks/terry_usb.json` |
| `ndlc_leakage_pc` | `cold_box_room/e2e/benchmarks/ndlc_leakage_pc.json` |
| `dfrws2008` | `cold_box_room/e2e/benchmarks/dfrws2008.json` |
