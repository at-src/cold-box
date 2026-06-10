# Brain Comparison — Policy vs. LLM (apples-to-apples)

_Both brains run the identical tool catalog, verifier, and scoring harness over
the same 8-case corpus and the same ground truth. The only variable is the
reasoner: the deterministic **policy** reasoner vs. the **LLM** reasoner
(`claude-sonnet-4-6`)._ Reproduce with:

```bash
# policy baseline
python scripts/benchmark.py --manifest ground-truth/benchmark-manifest.json --score-only
# llm
python scripts/benchmark.py --manifest ground-truth/benchmark-manifest-llm.json --out docs/ACCURACY-REPORT-LLM.md
```

## Side-by-side

| Case | Policy req-recall | LLM req-recall | Policy recall | LLM recall | Policy precision | LLM precision |
|------|:----:|:----:|:----:|:----:|:----:|:----:|
| `nist-ndlc` (USB exfil) | **1.00** | 0.00 | 0.50 | 0.33 | 1.00 | 1.00 |
| `ali-hadi-1` (Win intrusion) | 0.80 | 0.80 | 0.71 | 0.71 | 1.00 | 1.00 |
| `nitroba` (network/pcap) | 1.00 | 1.00 | 1.00 | 1.00 | 0.75 | 0.75 |
| `dfrws2008` (Linux) | 1.00 | 1.00 | 0.75 | 0.75 | 0.75 | 0.60 |
| `ali-hadi-7` (Win malware) | 0.50 | 0.50 | 0.50 | 0.50 | 1.00 | 1.00 |
| `ali-hadi-9` (restraint test) | 1.00 | 1.00 | 0.50 | 0.50 | 0.50 | 0.33 |
| `nist-hacking` (XP) | 1.00 | 1.00 | 0.67 | 0.67 | 1.00 | 1.00 |
| `dart-sample` (functional) | 0.33 | **1.00** | 0.60 | **1.00** | 0.43 | 0.62 |
| **mean** | **0.79** | **0.79** | 0.65 | **0.68** | **0.80** | 0.79 |

## Takeaways

1. **Aggregate parity, different strengths.** Required-recall ties at 0.79;
   the LLM brain has marginally higher overall recall (0.68 vs 0.65) and the
   policy brain marginally higher precision (0.80 vs 0.79).

2. **Policy brain is more reliable on its core competency.** On `nist-ndlc`
   the policy reasoner deterministically runs `disk_parse_usb` (a
   coverage-guaranteed rule) and nails the removable-storage exfil
   (required-recall 1.00). The LLM brain **never called `disk_parse_usb`**
   (it ran prefetch/registry/MFT/search instead) and missed it
   (required-recall 0.00). Deterministic coverage rules trade flexibility for
   guaranteed completeness on known artifact classes.

3. **LLM brain generalizes better to novel/unstructured evidence.** On the
   DART sample it lifts required-recall 0.33 -> 1.00 and recall 0.60 -> 1.00,
   surfacing findings the fixed policy did not reach.

4. **LLM is slightly noisier.** It tends to emit one or two extra findings
   (`dfrws2008` precision 0.75 -> 0.60, `ali-hadi-9` 0.50 -> 0.33), which is
   why precision dips even where recall holds.

5. **Implication — hybrid is best.** Run the LLM reasoner *with* the policy
   coverage guarantees as a floor: keep the LLM's breadth on unstructured
   evidence while never skipping a high-value deterministic check (USB, USN,
   persistence). The `nist-ndlc` miss is the concrete motivation.

_Self-correction fires under both brains; every finding in both modes carries
an `audit_id` and a verifier-grounded claim._
