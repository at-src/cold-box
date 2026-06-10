---
name: Injection follow-up
when_to_use: Verifier R7 fired or malfind/injection is suspected after process triage
---

# Injection follow-up

Run after R1 hidden-process or when memory triage suggests code injection.

## Tools

| Tool | Use |
|------|-----|
| `mem_malfind` | RWX / injected regions (R7) |
| `mem_dlllist` | Loaded modules for suspicious PID |
| `mem_cmdline` | Args for hidden PID |
| `mem_handles` | Unusual handles on target process |
| `mem_pstree` | Parent chain for injected process |

Do not downgrade R7 without re-running supporting tools or marking the item unresolved with audit citations.
