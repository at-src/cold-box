# cold-box-room

Deterministic hallway rooms for cold-box DFIR. Design: [design.md](design.md).

**Room 1 (R1)** — raw evidence in the R1 staging area, sealed read-only, checkpoint before Room 2.

**Room 2 (R2)** — sandbox workspace; evidence copied from R1 on promotion. SIFT tools via MCP; Layer 1 logbook (tool log + analyst log).

```bash
pip install -e ".[dev]"
export COLD_BOX_R1_STAGING=/path/to/r1-staging
export COLD_BOX_R2_SANDBOX=/path/to/r2-sandbox
export COLD_BOX_ROOM_RECORDS=/path/to/records

cold-box-room paths
cold-box-room intake --case-id m57-jo --source /path/to/jo-2009-12-11-002.E01
cold-box-room r1-status --case-id m57-jo
cold-box-room r1-check --case-id m57-jo --promote
cold-box-room r2-status --case-id m57-jo
cold-box-room sandbox-ls --case-id m57-jo
cold-box-room layer1-status --case-id m57-jo
cold-box-room r2-check --case-id m57-jo
cold-box-room staging-ls --case-id m57-jo
```
