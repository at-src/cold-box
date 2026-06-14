---
name: cb-deploying-decoy-files-for-ransomware-detection
skill_id: cb-deploying-decoy-files-for-ransomware-detection
journal_id: CB-SKL-169
description: Cold-box analyst playbook — Deploying Decoy Files For Ransomware Detection.
  Deploys canary files (honeytokens) across file systems to detect ransomware encryption
  activity in real time. Uses strategically placed decoy documents monitored via file
  integrity monitoring or OS-level watchdogs to trigger alerts when ran
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
- detection
- canary-files
- honeytokens
- deception
- file-integrity
cold_box_version: 2
inspired_by: deploying-decoy-files-for-ransomware-detection
---

# Deploying Decoy Files For Ransomware Detection (cold-box)

> **Journal ID:** `CB-SKL-169` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-169`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-deploying-decoy-files-for-ransomware-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-deploying-decoy-files-for-ransomware-detection")` → note **`CB-SKL-169`**
2. `log_skill(case_id, journal_id="CB-SKL-169", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-169` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Setting up early-warning detection for ransomware on file servers or endpoints
- Supplementing EDR/AV with a deception-based detection layer that catches unknown ransomware variants
- Creating high-fidelity ransomware alerts that have very low false-positive rates (legitimate users have no reason to touch decoy files)
- Testing ransomware response procedures by validating that canary file modifications trigger the expected alerting pipeline
- Protecting high-value file shares (finance, HR, legal) with tripwire files that indicate unauthorized encryption activity

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sort` | `SIFT-020` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-169] sort per playbook step",
  "why": "Executing cb-deploying-decoy-files-for-ransomware-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-169] file per playbook step",
  "why": "Executing cb-deploying-decoy-files-for-ransomware-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-169` (`cb-deploying-decoy-files-for-ransomware-detection`)

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

- Setting up early-warning detection for ransomware on file servers or endpoints
- Supplementing EDR/AV with a deception-based detection layer that catches unknown ransomware variants
- Creating high-fidelity ransomware alerts that have very low false-positive rates (legitimate users have no reason to touch decoy files)
- Testing ransomware response procedures by validating that canary file modifications trigger the expected alerting pipeline
- Protecting high-value file shares (finance, HR, legal) with tripwire files that indicate unauthorized encryption activity

**Do not use** decoy files as the sole ransomware defense. They are a detection mechanism, not a prevention mechanism, and should complement backups, EDR, and access controls.

## Prerequisites

- Python 3.8+ with `watchdog` library for cross-platform file system monitoring
- Administrative access to target file shares or endpoints for canary placement
- File integrity monitoring (FIM) tool or SIEM integration for alert routing
- Understanding of target directory structure to place canaries in high-value locations
- Windows: NTFS change journal or ReadDirectoryChangesW API access
- Linux: inotify support in kernel (standard in modern kernels)

## Workflow

### Step 1: Design Canary File Strategy

Plan file placement for maximum detection coverage:

```
Canary File Placement Strategy:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Naming Convention:
  - Use names that sort FIRST and LAST alphabetically in each directory
  - Ransomware typically enumerates directories A-Z or Z-A
  - Examples: _AAAA_budget_2024.docx, ~zzzz_report_final.xlsx

Placement Locations:
  - Root of every file share (\\server\share\_AAAA_canary.docx)
  - Desktop, Documents, Downloads on each endpoint
  - Department-specific shares (Finance, HR, Legal)
  - Backup staging directories
  - Home directories of high-privilege accounts

File Types:
  - .docx, .xlsx, .pdf (most targeted by ransomware)
  - .sql, .bak (database files, high value)
  - Mix of file types to detect ransomware that targets specific extensions
```

### Step 2: Generate Realistic Canary Files

Create decoy files with realistic content and metadata:

```python
import os
import time

def create_canary_docx(filepath, content="Q4 Financial Summary - Confidential"):
    """Create a realistic .docx canary file using python-docx."""
    from docx import Document
    doc = Document()
    doc.add_heading("Financial Report - CONFIDENTIAL", level=1)
    doc.add_paragraph(content)
    doc.add_paragraph(f"Generated: {time.strftime('%Y-%m-%d')}")
    doc.save(filepath)

def create_canary_txt(filepath):
    """Create a simple text canary with known content for hash verification."""
    content = "CANARY_TOKEN_DO_NOT_MODIFY\n"
    content += f"Created: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
    content += "This file is monitored for unauthorized changes.\n"
    with open(filepath, "w") as f:
        f.write(content)
```

### Step 3: Deploy File System Watcher

Monitor canary files for any modification, rename, or deletion:

```python
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, canary_paths, alert_callback):
        self.canary_paths = set(canary_paths)
        self.alert_callback = alert_callback

    def on_modified(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("DELETED", event.src_path)

    def on_moved(self, event):
        if event.src_path in self.canary_paths:
            self.alert_callback("RENAMED", event.src_path)
```

### Step 4: Configure Alerting and Response

Define automated responses when canary files are triggered:

```
Alert Response Matrix:
━━━━━━━━━━━━━━━━━━━━━
Event: Canary MODIFIED
  → Severity: CRITICAL
  → Action: Alert SOC, identify modifying process (PID), isolate endpoint

Event: Canary DELETED
  → Severity: HIGH
  → Action: Alert SOC, check for ransomware note in same directory

Event: Canary RENAMED (new extension added)
  → Severity: CRITICAL
  → Action: Alert SOC, check extension against known ransomware extensions
  → Automated: Kill modifying process, disable network interface

Event: Multiple canaries triggered within 60 seconds
  → Severity: EMERGENCY
  → Action: Network-wide isolation, activate incident response plan
```

### Step 5: Validate Detection Coverage

Test that canary files detect actual ransomware behavior:

```bash
# Simulate ransomware encryption (safe test - modifies canary content)
echo "ENCRYPTED_BY_TEST" > /path/to/canary/_AAAA_budget.docx

# Simulate ransomware rename (adds extension)
mv /path/to/canary/report.xlsx /path/to/canary/report.xlsx.locked

# Verify alerts were generated in SIEM/alerting system
```

## Verification

- Confirm all canary files are present and unmodified using stored hash baselines
- Verify that modifying any canary file generates an alert within the expected timeframe (under 30 seconds)
- Test that alert routing to SOC/SIEM is functional with a controlled modification
- Validate that automated response actions (process kill, network isolation) execute correctly
- Check that canary files survive normal backup and restore operations
- Ensure legitimate users and processes are excluded from false-positive alerts (backup agents, AV scans)

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | A decoy file placed in a directory that is monitored for any access or modification, serving as a tripwire for unauthorized activity |
| **Honeytoken** | A broader category of deception artifacts (files, credentials, database records) designed to alert when accessed |
| **File Integrity Monitoring** | Continuous monitoring of file attributes (hash, size, permissions, timestamps) to detect unauthorized changes |
| **ReadDirectoryChangesW** | Windows API for monitoring file system changes in a directory; used by the watchdog library on Windows |
| **inotify** | Linux kernel subsystem for monitoring file system events; provides near-instant notification of file changes |

## Tools & Systems

- **watchdog (Python)**: Cross-platform file system event monitoring library supporting Windows, Linux, and macOS
- **Canarytokens (Thinkst)**: Free hosted service for generating various types of canary tokens including files, URLs, and DNS tokens
- **OSSEC/Wazuh**: Open-source HIDS with built-in file integrity monitoring and alerting capabilities
- **Elastic Endpoint**: Uses canary files internally for ransomware protection and key capture
- **Sysmon**: Windows system monitor that logs file creation events (Event ID 11) for canary file monitoring

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
