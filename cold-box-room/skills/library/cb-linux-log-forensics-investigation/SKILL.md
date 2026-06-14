---
name: cb-linux-log-forensics-investigation
skill_id: cb-linux-log-forensics-investigation
journal_id: CB-SKL-072
description: Cold-box analyst playbook — Linux Log Forensics Investigation. Perform
  forensic investigation of Linux system logs including syslog, auth.log, systemd
  journal, kern.log, and application logs to reconstruct user activity, detect unauthorized
  access, and establish event timelines on compromised Linux sys
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- linux_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- linux-forensics
- syslog
- auth-log
- systemd-journal
- journalctl
- linux-logs
- ssh-forensics
- cron
- audit-log
- log-analysis
cold_box_version: 2
inspired_by: performing-linux-log-forensics-investigation
---

# Linux Log Forensics Investigation (cold-box)

> **Journal ID:** `CB-SKL-072` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-072`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-linux-log-forensics-investigation")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-linux-log-forensics-investigation")` → note **`CB-SKL-072`**
2. `log_skill(case_id, journal_id="CB-SKL-072", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-072` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing linux log forensics investigation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `head` | `SIFT-011` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `uniq` | `SIFT-025` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `awk` | `SIFT-005` | yes | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `head` → `SIFT-011`

```json
{
  "tool_id": "SIFT-011",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] head per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] sort per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] grep per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] find per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `uniq` → `SIFT-025`

```json
{
  "tool_id": "SIFT-025",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] uniq per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] file per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `awk` → `SIFT-005`

```json
{
  "tool_id": "SIFT-005",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] awk per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

### `ls` → `SIFT-014`

```json
{
  "tool_id": "SIFT-014",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-072] ls per playbook step",
  "why": "Executing cb-linux-log-forensics-investigation \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-072` (`cb-linux-log-forensics-investigation`)

- **action:** adopted | step | finding | deferred | completed
- **note:** What you did or concluded under this playbook
- **related_audit_ids:** (optional) CB-… from run_sift_tool
```

Or call MCP: `log_skill(case_id, journal_id="{journal_id}", action="adopted", note="...")`

## Cold-box path translation

When the procedure below uses host paths, translate as follows:

| Procedure path | Cold-box equivalent |
|----------------|---------------------|
| `C:\Evidence\...` / `/cases/...` | `{input_relpath}` on the sealed table (via viewport) |
| `C:\Output\...` / `/analysis/...` | `records/{case_id}/scratch/` (tool stdout/files) |
| Live SIEM / cloud console steps | **Reference only** on cold-box — note capability gap in journal |

Do not copy evidence off the table except into `records/{case_id}/scratch/` via `run_sift_tool`.


## Procedure

## Overview

Linux systems maintain extensive logs that serve as primary evidence sources in forensic investigations. Unlike Windows Event Logs, Linux logs are typically plain-text files stored in /var/log/ and binary journal files managed by systemd-journald. Key forensic logs include auth.log (authentication events, sudo usage, SSH sessions), syslog (system-wide messages), kern.log (kernel events), and application-specific logs. The Linux Audit framework (auditd) provides detailed security event logging comparable to Windows Security Event Logs. Forensic analysis of these logs enables investigators to reconstruct user sessions, identify unauthorized access, detect privilege escalation, trace lateral movement, and establish comprehensive event timelines.


## When to Use

- When conducting security assessments that involve performing linux log forensics investigation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Familiarity with digital forensics concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Log Files and Locations

| Log File | Path | Contents |
|----------|------|----------|
| auth.log / secure | /var/log/auth.log (Debian) or /var/log/secure (RHEL) | Authentication, sudo, SSH, PAM |
| syslog / messages | /var/log/syslog (Debian) or /var/log/messages (RHEL) | General system messages |
| kern.log | /var/log/kern.log | Kernel messages, USB events, driver loads |
| lastlog | /var/log/lastlog | Last login per user (binary) |
| wtmp | /var/log/wtmp | Login/logout records (binary, read with `last`) |
| btmp | /var/log/btmp | Failed login attempts (binary, read with `lastb`) |
| faillog | /var/log/faillog | Failed login counter (binary) |
| cron.log | /var/log/cron or /var/log/syslog | Scheduled task execution |
| audit.log | /var/log/audit/audit.log | Linux Audit Framework events |
| journal | /var/log/journal/ or /run/log/journal/ | systemd binary journal |
| dpkg.log | /var/log/dpkg.log | Package installation/removal (Debian) |
| yum.log | /var/log/yum.log | Package installation/removal (RHEL) |

## Analysis Techniques

### Authentication Log Analysis

```bash
# Find all successful SSH logins
grep "Accepted" /var/log/auth.log

# Find failed SSH login attempts
grep "Failed password" /var/log/auth.log

# Extract unique source IPs from failed logins
grep "Failed password" /var/log/auth.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort -u

# Find sudo command execution
grep "sudo:" /var/log/auth.log | grep "COMMAND"

# Detect brute force patterns (>10 failures from same IP)
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Find account creation events
grep "useradd\|adduser" /var/log/auth.log

# Detect SSH key authentication
grep "Accepted publickey" /var/log/auth.log
```

### Systemd Journal Analysis

```bash
# Export journal in JSON format for forensic processing
journalctl --output=json --no-pager > journal_export.json

# Filter by time range
journalctl --since "2025-02-01" --until "2025-02-15" --output=json > timerange.json

# Filter by unit/service
journalctl -u sshd --output=json > sshd_journal.json

# Show kernel messages (USB events, module loads)
journalctl -k --output=json > kernel_journal.json

# Filter by priority (0=emerg to 7=debug)
journalctl -p err --output=json > errors.json

# Boot-specific logs
journalctl -b 0 --output=json > current_boot.json
journalctl --list-boots  # List all recorded boot sessions
```

### Linux Audit Framework Analysis

```bash
# Search audit log for specific event types
ausearch -m USER_AUTH --start today

# Search for file access events
ausearch -f /etc/shadow

# Search for process execution
ausearch -m EXECVE --start "02/01/2025" --end "02/28/2025"

# Generate report of login events
aureport --login --start "02/01/2025"

# Generate summary of failed authentications
aureport --auth --failed

# Search for specific user activity
ausearch -ua 1001  # By UID
ausearch -ua username  # By username
```

### Cron Job Investigation

```bash
# Check system-wide crontab
cat /etc/crontab

# Check user crontabs
ls -la /var/spool/cron/crontabs/

# Review cron execution logs
grep "CRON" /var/log/syslog

# Check for at/batch jobs
ls -la /var/spool/at/
atq
```

## Python Forensic Log Parser

```python
import re
import json
import sys
import os
from datetime import datetime
from collections import defaultdict


class LinuxLogForensicAnalyzer:
    """Analyze Linux system logs for forensic investigation."""

    def __init__(self, log_dir: str, output_dir: str):
        self.log_dir = log_dir
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def parse_auth_log(self, auth_log_path: str) -> dict:
        """Parse auth.log for authentication events."""
        events = {
            "successful_logins": [],
            "failed_logins": [],
            "sudo_commands": [],
            "account_changes": [],
            "ssh_sessions": []
        }

        ssh_accepted = re.compile(
            r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+([\d.]+)'
        )
        ssh_failed = re.compile(
            r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(\S*)\s+from\s+([\d.]+)'
        )
        sudo_cmd = re.compile(
            r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)'
        )
        useradd = re.compile(
            r'(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+useradd\[\d+\]:\s+new user: name=(\S+)'
        )

        with open(auth_log_path, "r", errors="replace") as f:
            for line in f:
                m = ssh_accepted.search(line)
                if m:
                    events["successful_logins"].append({
                        "timestamp": m.group(1), "host": m.group(2),
                        "method": m.group(3), "user": m.group(4), "source_ip": m.group(5)
                    })
                    continue

                m = ssh_failed.search(line)
                if m:
                    events["failed_logins"].append({
                        "timestamp": m.group(1), "host": m.group(2),
                        "user": m.group(3), "source_ip": m.group(4)
                    })
                    continue

                m = sudo_cmd.search(line)
                if m:
                    events["sudo_commands"].append({
                        "timestamp": m.group(1), "host": m.group(2),
                        "user": m.group(3), "command": m.group(4).strip()
                    })
                    continue

                m = useradd.search(line)
                if m:
                    events["account_changes"].append({
                        "timestamp": m.group(1), "host": m.group(2),
                        "new_user": m.group(3)
                    })

        return events

    def detect_brute_force(self, auth_events: dict, threshold: int = 10) -> list:
        """Detect brute force attempts from auth log data."""
        ip_failures = defaultdict(int)
        for event in auth_events.get("failed_logins", []):
            ip_failures[event["source_ip"]] += 1

        brute_force = []
        for ip, count in ip_failures.items():
            if count >= threshold:
                brute_force.append({"source_ip": ip, "failed_attempts": count})

        return sorted(brute_force, key=lambda x: x["failed_attempts"], reverse=True)

    def generate_report(self, auth_log_path: str) -> str:
        """Generate comprehensive forensic analysis report."""
        auth_events = self.parse_auth_log(auth_log_path)
        brute_force = self.detect_brute_force(auth_events)

        report = {
            "analysis_timestamp": datetime.now().isoformat(),
            "log_source": auth_log_path,
            "summary": {
                "successful_logins": len(auth_events["successful_logins"]),
                "failed_logins": len(auth_events["failed_logins"]),
                "sudo_commands": len(auth_events["sudo_commands"]),
                "account_changes": len(auth_events["account_changes"]),
                "brute_force_sources": len(brute_force)
            },
            "brute_force_detected": brute_force,
            "auth_events": auth_events
        }

        report_path = os.path.join(self.output_dir, "linux_log_forensics.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"[*] Successful logins: {report['summary']['successful_logins']}")
        print(f"[*] Failed logins: {report['summary']['failed_logins']}")
        print(f"[*] Sudo commands: {report['summary']['sudo_commands']}")
        print(f"[*] Brute force sources: {report['summary']['brute_force_sources']}")
        return report_path


def main():
    if len(sys.argv) < 3:
        print("Usage: python process.py <auth_log_path> <output_dir>")
        sys.exit(1)
    analyzer = LinuxLogForensicAnalyzer(os.path.dirname(sys.argv[1]), sys.argv[2])
    analyzer.generate_report(sys.argv[1])


if __name__ == "__main__":
    main()
```

## References

- Linux Forensics In Depth: https://amr-git-dot.github.io/forensic%20investigation/Linux_Forensics/
- SANS Practical Linux Forensics: https://nostarch.com/linuxforensics
- HackTricks Linux Forensics: https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/linux-forensics
- Log Sources for Digital Forensics: https://letsdefend.io/blog/log-sources-for-digital-forensics-windows-and-linux

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
