---
name: Registry and Windows persistence
when_to_use: Registry hives, Run keys CSV, services CSV, scheduled tasks, or setupapi.dev.log present
---

# Registry and Windows persistence

Run when survey lists `registry_hive`, `registry_export`, `services_csv`, `scheduled_task`, or `setupapi_log`.

## Tools

| Tool | Use |
|------|-----|
| `disk_parse_setupapi` | USB / IP-KVM insertion (R12) |
| `disk_parse_scheduled_tasks` | Task XML persistence (R13) |
| `reg_run_keys` | Run/RunOnce keys |
| `reg_services` | Ghost service ImagePath (R11) |
| `reg_amcache` | First execution (R2) |
| `disk_parse_shimcache` | Execution history without prefetch |

Investigate USB insertion before attributing logon-only activity. Cross-check services whose binary is missing from the evidence tree (R11).
