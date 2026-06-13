# cold-box

Deterministic hallway rooms for cold-box DFIR — enforced in code, not prose.

**Current tree:** [cold-box-room/](cold-box-room/) (R1 staging + R2 sandbox). Full spec: [cold-box-room/design.md](cold-box-room/design.md).

## Quick start

```bash
cd cold-box-room
pip install -e ".[dev]"

export COLD_BOX_R1_STAGING=/path/to/r1-staging
export COLD_BOX_R2_SANDBOX=/path/to/r2-sandbox
export COLD_BOX_ROOM_RECORDS=/path/to/records

cold-box-room paths
cold-box-room intake --case-id CASE --source /path/to/evidence.E01
cold-box-room r1-check --case-id CASE --promote
cold-box-room r2-status --case-id CASE
```

## History

Earlier iterations (agent harness, evidence tooling, benchmarks, skills) are **not in this tree** but remain in **git history**. Browse older commits on `main` to see how the project evolved to the hallway design.
