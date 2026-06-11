# Investigation modes (policy, hybrid, LLM)

Postmortem ships three **brains** for the same verifier-backed toolchain. Judges and the cold-box benchmark score **`policy`** (no LLM) as the primary submission mode; hybrid and LLM are exploratory orderings over the same tools and rules.

## Policy (default, scored)

- **What it is:** Deterministic evidence-driven reasoner (`postmortem_agent/reasoner_policy.py`).
- **How it picks tools:** Survey kinds → coverage gaps for verifier rules R1–R31 → priority frontier (ingest-first on raw images, then typed parsers, then breadth scans).
- **Findings:** Built only from verifier contradictions, peak signals preserved across the run, and small optional GT helpers (web-server logons, hosts-file inference, etc.).
- **When to use:** Reproducible benchmarks, CI, hackathon scoring.

```bash
python -m postmortem_agent.cli run --case-id nist-ndlc --evidence-case nist-pc-only
```

## Hybrid

- **What it is:** Policy **coverage floor** (must-run tools for each case class) plus LLM **ordering** among remaining frontier actions.
- **Same verifier, same findings pipeline** as policy once tools complete.
- **When to use:** Demos where you want natural-language rationale without giving up coverage guarantees.

```bash
python -m postmortem_agent.cli run --case-id ali-hadi-1 --evidence-case ali-hadi-1 --hybrid
```

## LLM

- **What it is:** LLM chooses each next tool from the catalog subject to basic guards; no policy coverage floor.
- **Higher variance** — useful for ablation, not the canonical accuracy number.
- **Requires** `ANTHROPIC_API_KEY` in repo `.env`.

```bash
python -m postmortem_agent.cli run --case-id nitroba --evidence-case nitroba --llm
```

## Parity expectations

| Capability | Policy | Hybrid | LLM |
|------------|--------|--------|-----|
| Verifier rules R1–R31 | yes | yes | yes |
| Audit trail / `audit_id` on findings | yes | yes | yes |
| Coverage floor (Tier 1–3 tools) | yes | yes | partial |
| Self-correction in `progress.jsonl` | yes | yes | yes |
| Reproducible cold-box scores | **yes** | no | no |

**Bottom line:** Policy is the scored brain. Hybrid adds LLM narration/order on top of the same engine. LLM-only trades coverage for flexibility.

See `docs/ACCURACY-REPORT.md` for per-case required recall and strict recall, and `ground-truth/*.json` for optional vs required GT items.
