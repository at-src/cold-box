# Accuracy Report — hybrid benchmark (policy floor + LLM)

_Generated: 2026-06-11 (post coverage expansion)_

Run with `source bin/load-agent-env` (or `scripts/benchmark.py` auto-loads repo `.env`).

| Case | Required recall | Recall | Precision | Missed (required) |
|------|-----------------|--------|-----------|-------------------|
| `nist-ndlc-hybrid` | 1.00 | 0.67 | 0.67 | — |
| `ali-hadi-1-hybrid` | 1.00 | 0.71 | 0.83 | — |
| `nitroba-hybrid` | 1.00 | 0.67 | 0.67 | — |
| `dfrws2008-hybrid` | 1.00 | 0.75 | 0.60 | — |
| `ali-hadi-7-hybrid` | 1.00 | 0.75 | 1.00 | — |
| `ali-hadi-9-hybrid` | 1.00 | 0.00 | 0.00 | — (restraint test) |
| `nist-hacking-hybrid` | 1.00 | 1.00 | 0.75 | — |
| `dart-sample-evidence-hybrid` | 1.00 | 1.00 | 0.56 | — |

**Mean required-recall: 1.00** (after R12 setupapi coverage + benchmark `.env` load).

`ali-hadi-9-hybrid` still scores precision ~0 on optional restraint keywords when the LLM over-calls; policy brain is preferred for that case.
