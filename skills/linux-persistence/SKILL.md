---
name: Linux persistence
when_to_use: Survey shows linux_log, cron, bash_history, or var/log paths on a Linux host segment
---

# Linux persistence

Run when the case tree includes auth logs, cron, or user history under Linux paths.

## Tools

| Tool | Use |
|------|-----|
| `linux_persistence` | Breadth sweep (R10) |
| `linux_cron` | Scheduled commands |
| `linux_bash_history` | Suspicious one-liners |
| `linux_auth_log` | Failed/remote logins |

Pair `linux_persistence` with verifier R10. Do not claim persistence without an audit_id from a Linux tool.
