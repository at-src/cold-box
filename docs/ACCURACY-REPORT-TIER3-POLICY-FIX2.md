# Accuracy Report — cold-box benchmark

_Generated: 2026-06-11T10:34:27.906659+00:00_

Required-recall is over findings the engine is designed to surface; overall
recall includes known coverage gaps (documented per case in `ground-truth/`).

| Case | Tier | Brain | Required recall | Recall | Precision | Matched | Missed (required) |
|------|------|-------|-----------------|--------|-----------|---------|-------------------|
| `nist-ndlc` | validation (Tier 1) | policy | 1.00 | 0.83 | 1.00 | 5 | — |
| `dfrws2008` | validation (Tier 2) — Linux disk+mem+net | policy | 1.00 | 1.00 | 0.44 | 4 | — |
