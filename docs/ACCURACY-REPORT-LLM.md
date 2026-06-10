# Accuracy Report — cold-box benchmark

_Generated: 2026-06-10T21:30:06.506630+00:00_

Required-recall is over findings the engine is designed to surface; overall
recall includes known coverage gaps (documented per case in `ground-truth/`).

| Case | Tier | Brain | Required recall | Recall | Precision | Matched | Missed (required) |
|------|------|-------|-----------------|--------|-----------|---------|-------------------|
| `nist-ndlc-llm` | validation (Tier 1) | llm | 0.00 | 0.33 | 1.00 | 2 | F-USB-EXFIL |
| `ali-hadi-1-llm` | validation (Tier 2) | llm | 0.80 | 0.71 | 1.00 | 5 | AH-1 |
| `nitroba-llm` | validation (Tier 1) | llm | 1.00 | 1.00 | 0.75 | 3 | — |
| `dfrws2008-llm` | validation (Tier 2) — Linux disk+mem+net | llm | 1.00 | 0.75 | 0.60 | 3 | — |
| `ali-hadi-7-llm` | validation (Tier 2) — Windows malware/persistence | llm | 0.50 | 0.50 | 1.00 | 2 | F-FAKE-VMWARE-SERVICE |
| `ali-hadi-9-llm` | validation (Tier 2) — false-positive / restraint test | llm | 1.00 | 0.50 | 0.33 | 1 | — |
| `nist-hacking-llm` | validation (Tier 1) — Windows XP split-raw | llm | 1.00 | 0.67 | 1.00 | 2 | — |
| `dart-sample-evidence-llm` | functional | llm | 1.00 | 1.00 | 0.62 | 5 | — |
