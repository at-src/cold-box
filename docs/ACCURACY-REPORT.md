# Accuracy Report — cold-box benchmark

_Generated: 2026-06-10T19:55:42.604420+00:00_

Required-recall is over findings the engine is designed to surface; overall
recall includes known coverage gaps (documented per case in `ground-truth/`).

| Case | Tier | Brain | Required recall | Recall | Precision | Matched | Missed (required) |
|------|------|-------|-----------------|--------|-----------|---------|-------------------|
| `nist-ndlc` | validation (Tier 1) | policy | 1.00 | 0.50 | 1.00 | 3 | — |
| `ali-hadi-1` | validation (Tier 2) | policy | 0.80 | 0.71 | 1.00 | 5 | AH-1 |
| `nitroba` | validation (Tier 1) | policy | 1.00 | 1.00 | 0.75 | 3 | — |
| `dart-sample-evidence` | functional | policy | 0.33 | 0.60 | 0.43 | 3 | F-001, F-003 |
