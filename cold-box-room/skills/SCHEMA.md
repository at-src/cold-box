# Skill catalog schema (`skills/manifest.json`)

Layer 2 analysis recipes for Room 3. The agent discovers skills via `list_skills` / `describe_skill` (Room B browse, Room 3 execution). Deterministic runs go through `run_skill(skill_id=…)` — **not MCP**, not a DB.

Machine validation: `skills/manifest.schema.json`.

## Design rules

| Skills are | Skills are not |
|------------|----------------|
| Deterministic `.py` recipes (`run(ctx)` → JSON) | Hidden SIFT runners |
| Methodology + structured output | Agent freeform math |
| Indexed by stable `SKILL-###` | Merged into `SIFT-###` catalog |

Recipe `.py` files must **not** call subprocess, shell out, or invoke tools. If new extraction is needed, return `needs_extraction` with `tool_id` hints — the agent uses `run_sift_tool` in Room 2.

## Top-level manifest

| Field | Type | Meaning |
|-------|------|---------|
| `schema` | string | `cold_box_room.skills_manifest_v1` |
| `count` | int | Must match `skills.length` |
| `skills` | array | Skill records |

## Each skill record

| Field | Meaning |
|-------|---------|
| **skill_id** | Stable id, e.g. `SKILL-001` — agent passes this to `run_skill` |
| **name** | Short snake_case name (`analyst_score_normalize`) |
| **recipe** | Path under `skills/` to the `.py` file (must export `run`) |
| **category** | Filter group (`methodology`, `windows-artifacts`, …) |
| **description** | Agent-facing summary (browse row) |
| **tags** | Free-form tags for filter/search |
| **artifact_platforms** | Evidence types (`any`, `windows`, …) |
| **inputs.scratch** | `required` / `optional` scratch relpath names (logical labels) |
| **inputs.params** | Param specs the agent passes to `run_skill` |
| **outputs** | `format` + `fields` the recipe returns in `data` |
| **suggested_tool_ids** | **Hints only** — not executed by the skill |
| **proof** | Harness proof contract for plan-step scoring (Room 3+) |

## Recipe file contract

Each `skills/recipes/SKILL-NNN_*.py`:

```python
SKILL_META = {"skill_id": "SKILL-001", "name": "…"}  # optional mirror

def run(ctx: SkillContext) -> dict:
    return {
        "ok": True,
        "data": { ... },           # deterministic JSON
        "scratch_refs": [],        # new scratch outputs, if any
        "needs_extraction": [],    # optional: [{tool_id, reason}]
    }
```

`ctx` provides `case_id`, `skill_id`, `scratch` (resolved paths), `params`.

## Batch 1 (ported from cold-box-final CB-SKL-001 … CB-SKL-050)

| skill_id | source | kind |
|----------|--------|------|
| SKILL-001 … SKILL-050 | CB-SKL-001 … CB-SKL-050 | see tags |

**Kinds in batch 1:**

| Kind | Count | Behavior |
|------|------:|----------|
| `orchestrate` playbook | 48 | Returns checklist + `suggested_tool_ids` — agent runs SIFT in Room 2 |
| `scratch_analyzer` | 2 | Deterministic sqlite parse on scratch (`SKILL-003`, `SKILL-041`) |

Skills tagged `ported-from-disguised-tool-script` had imported `agent.py` files that called external APIs or subprocess — only the playbook remains; tools stay in SIFT catalog.

Skills tagged `reference-only` describe live IR/SOC/cloud steps — use for planning; many steps need capability not on a dead-host disk image.

Regenerate batch 1: `python -m cold_box_room.skills.port_batch`

## Batches (target)

## Adding skills

1. Add `skills/recipes/SKILL-NNN_name.py` with `run()`.
2. Append manifest row; bump `count`.
3. Keep `skill_id` unique (`SKILL-###`).
4. Recipe must pass static validator (no subprocess / shell).
