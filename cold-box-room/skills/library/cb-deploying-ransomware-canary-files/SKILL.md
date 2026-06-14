---
name: cb-deploying-ransomware-canary-files
skill_id: cb-deploying-ransomware-canary-files
journal_id: CB-SKL-171
description: Cold-box analyst playbook — Deploying Ransomware Canary Files. Deploys
  and monitors ransomware canary files across critical directories using Python's
  watchdog library for real-time filesystem event detection. Places strategically
  named decoy files that mimic high-value targets (financial records, cred
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- canary-files
- watchdog
- detection
- early-warning
- deception
- defense
cold_box_version: 2
inspired_by: deploying-ransomware-canary-files
---

# Deploying Ransomware Canary Files (cold-box)

> **Journal ID:** `CB-SKL-171` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-171`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-deploying-ransomware-canary-files")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-deploying-ransomware-canary-files")` → note **`CB-SKL-171`**
2. `log_skill(case_id, journal_id="CB-SKL-171", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-171` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Deploying proactive ransomware detection on file servers, NAS devices, or endpoint systems
- Building an early-warning system that detects ransomware before it encrypts business-critical data
- Supplementing EDR solutions with lightweight canary file monitoring on systems where agents cannot be deployed
- Testing ransomware incident response procedures by simulating canary file triggers
- Monitoring shared drives, home directories, and backup volumes for unauthorized file operations

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-171] file per playbook step",
  "why": "Executing cb-deploying-ransomware-canary-files \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-171` (`cb-deploying-ransomware-canary-files`)

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

## When to Use

- Deploying proactive ransomware detection on file servers, NAS devices, or endpoint systems
- Building an early-warning system that detects ransomware before it encrypts business-critical data
- Supplementing EDR solutions with lightweight canary file monitoring on systems where agents cannot be deployed
- Testing ransomware incident response procedures by simulating canary file triggers
- Monitoring shared drives, home directories, and backup volumes for unauthorized file operations

**Do not use** as a replacement for endpoint protection, backup strategy, or network segmentation. Canary files are a detection layer, not a prevention mechanism.

## Prerequisites

- Python 3.8+ with pip
- watchdog library (pip install watchdog)
- Write access to directories where canary files will be placed
- SMTP server credentials or Slack webhook URL for alerting
- Administrative access for placing canaries in system directories

## Workflow

### Step 1: Generate Canary Files

Create decoy files with realistic names and content that attract ransomware scanners. Files should have names like `Passwords.xlsx`, `Financial_Report_2026.docx`, `backup_credentials.csv` and contain plausible-looking but fake data. Place them in directories ransomware typically targets first: user desktops, Documents folders, network share roots, and backup paths.

### Step 2: Deploy Filesystem Monitor

Use Python's watchdog library with a custom `FileSystemEventHandler` that watches canary file paths. The handler triggers on `on_modified`, `on_deleted`, `on_moved`, and `on_created` events for canary files. Any legitimate user or process should never touch these files, so any interaction is a high-confidence indicator of ransomware or unauthorized access.

### Step 3: Configure Alert Pipeline

Wire the filesystem monitor to multiple alert channels: email via SMTP, Slack webhook POST, syslog forwarding to SIEM, and local log file. Include the triggering event type, file path, timestamp, and process information (when available) in alert payloads.

### Step 4: Validate and Test

Simulate ransomware behavior by programmatically modifying, renaming, and deleting canary files to verify the detection pipeline fires correctly. Measure time-to-alert and validate alert delivery across all configured channels.

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | A decoy file placed in a monitored directory that triggers an alert when accessed, modified, or deleted |
| **Watchdog** | Python library that monitors filesystem events using OS-native APIs (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) |
| **Honey File** | Synonym for canary file; a fake document designed to attract and detect malicious activity |
| **Entropy Check** | Measuring randomness in file content to detect encryption (ransomware produces high-entropy output) |

## Tools & Systems

- **watchdog**: Python filesystem monitoring library using OS-native event APIs
- **smtplib**: Python standard library for SMTP email alerting
- **requests**: HTTP library for Slack webhook integration
- **hashlib**: SHA-256 hashing for canary file integrity verification
- **psutil**: Process information gathering when canary file access is detected

## Output Format

```
RANSOMWARE CANARY ALERT
========================
Timestamp: 2026-03-11T14:23:07Z
Event: FILE_MODIFIED
Canary File: /srv/shares/finance/Passwords.xlsx
Directory: /srv/shares/finance
SHA-256 Before: a3f2...8b4c
SHA-256 After: 7e91...2d3f
Alert Channels: [email, slack, syslog]
Action: Investigate immediately - potential ransomware activity
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
