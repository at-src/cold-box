---
name: Phantom logon hunt
when_to_use: Security EVTX is available and you need to reconcile authentication with memory sessions
---

# Phantom logon hunt

Run when survey includes `evtx` (especially Security.evtx).

## Tools

| Tool | Use |
|------|-----|
| `disk_evtx_filter` | Auth events 4624/4625/4648 |
| `disk_parse_evtx` | Full log when filter is too narrow |
| `mem_pslist` | Session IDs in memory |
| `timeline_super` | Merge logon time with USB/task/MFT |

Verifier R3 fires when a successful logon has no matching memory session. Resolve or mark unresolved before closing.
