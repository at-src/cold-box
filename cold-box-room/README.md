# cold-box-room

Deterministic hallway rooms for cold-box DFIR. Design: [design.md](design.md).

**Room 1 (R1)** — raw evidence in the R1 staging area, sealed read-only, checkpoint before Room 2.

```bash
pip install -e ".[dev]"
export COLD_BOX_R1_STAGING=/path/to/r1-staging
export COLD_BOX_ROOM_RECORDS=/path/to/records

cold-box-room paths
cold-box-room intake --case-id m57-jo --source /path/to/jo-2009-12-11-002.E01
cold-box-room r1-status --case-id m57-jo
cold-box-room r1-check --case-id m57-jo --promote
cold-box-room staging-ls --case-id m57-jo
```
