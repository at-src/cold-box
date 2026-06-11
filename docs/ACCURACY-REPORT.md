# Accuracy Report — cold-box benchmark

_Generated: 2026-06-11T14:38:24.017732+00:00_

Required-recall is over findings the engine is designed to surface; overall
recall includes known coverage gaps (documented per case in `ground-truth/`).

| Case | Tier | Brain | Required recall | Recall | Precision | Matched | Missed (required) |
|------|------|-------|-----------------|--------|-----------|---------|-------------------|
| `nist-ndlc` | validation (Tier 1) | policy | 1.00 | 1.00 | 0.75 | 6 | — |
| `ali-hadi-1` | validation (Tier 2) | policy | 1.00 | 1.00 | 0.78 | 7 | — |
| `nitroba` | validation (Tier 1) | policy | 1.00 | 1.00 | 0.75 | 3 | — |
| `dfrws2008` | validation (Tier 2) — Linux disk+mem+net | policy | 1.00 | 1.00 | 0.44 | 4 | — |
| `ali-hadi-7` | validation (Tier 2) — Windows malware/persistence | policy | 1.00 | 1.00 | 0.80 | 4 | — |
| `ali-hadi-9` | validation (Tier 2) — false-positive / restraint test | policy | 1.00 | 0.00 | 0.00 | 0 | — |
| `nist-hacking` | validation (Tier 1) — Windows XP split-raw | policy | 1.00 | 1.00 | 0.60 | 3 | — |
| `dart-sample-evidence` | functional | policy | 1.00 | 1.00 | 0.42 | 5 | — |
| `dfrws2011-android-case1` | validation (Tier 3) — Android mtd/sdcard | policy | 1.00 | 1.00 | 0.67 | 2 | — |
| `dfrws2011-android-case2` | validation (Tier 3) — Android mtd/sdcard Case2 | policy | 1.00 | 1.00 | 0.67 | 2 | — |
| `macos-spotlight` | validation (Tier 3) — macOS AD1 Spotlight | policy | 1.00 | 1.00 | 0.67 | 2 | — |
