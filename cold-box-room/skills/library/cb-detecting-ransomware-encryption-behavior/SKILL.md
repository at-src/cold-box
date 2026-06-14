---
name: cb-detecting-ransomware-encryption-behavior
skill_id: cb-detecting-ransomware-encryption-behavior
journal_id: CB-SKL-205
description: Cold-box analyst playbook — Detecting Ransomware Encryption Behavior.
  Detects ransomware encryption activity in real time using entropy analysis, file
  system I/O monitoring, and behavioral heuristics. Identifies mass file modification
  patterns, abnormal entropy spikes in written data, and suspicious process b
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
- entropy
- behavioral-analysis
- file-monitoring
- heuristics
cold_box_version: 2
inspired_by: detecting-ransomware-encryption-behavior
---

# Detecting Ransomware Encryption Behavior (cold-box)

> **Journal ID:** `CB-SKL-205` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-205`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-ransomware-encryption-behavior")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-ransomware-encryption-behavior")` → note **`CB-SKL-205`**
2. `log_skill(case_id, journal_id="CB-SKL-205", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-205` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Building or tuning a behavioral detection layer for ransomware that catches unknown/zero-day variants
- Monitoring file servers and endpoints for mass encryption activity that evades signature-based detection
- Implementing entropy-based detection to identify when files are being replaced with encrypted (high-entropy) content
- Analyzing suspicious process behavior patterns: rapid sequential file opens, writes, renames, and deletes
- Validating EDR detection rules against actual ransomware encryption patterns during red team exercises

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `wmic` | `SIFT-186` | no | no |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `7z` | `SIFT-046` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-205] powershell per playbook step",
  "why": "Executing cb-detecting-ransomware-encryption-behavior \u2014 see Procedure section",
  "extra_args": []
}
```

### `wmic` → `SIFT-186`

```json
{
  "tool_id": "SIFT-186",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-205] wmic per playbook step",
  "why": "Executing cb-detecting-ransomware-encryption-behavior \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-205] file per playbook step",
  "why": "Executing cb-detecting-ransomware-encryption-behavior \u2014 see Procedure section",
  "extra_args": []
}
```

### `zip` → `SIFT-036`

```json
{
  "tool_id": "SIFT-036",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-205] zip per playbook step",
  "why": "Executing cb-detecting-ransomware-encryption-behavior \u2014 see Procedure section",
  "extra_args": []
}
```

### `7z` → `SIFT-046`

```json
{
  "tool_id": "SIFT-046",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-205] 7z per playbook step",
  "why": "Executing cb-detecting-ransomware-encryption-behavior \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-205` (`cb-detecting-ransomware-encryption-behavior`)

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

- Building or tuning a behavioral detection layer for ransomware that catches unknown/zero-day variants
- Monitoring file servers and endpoints for mass encryption activity that evades signature-based detection
- Implementing entropy-based detection to identify when files are being replaced with encrypted (high-entropy) content
- Analyzing suspicious process behavior patterns: rapid sequential file opens, writes, renames, and deletes
- Validating EDR detection rules against actual ransomware encryption patterns during red team exercises

**Do not use** entropy analysis alone as the only detection signal. Compressed files (ZIP, JPEG, MP4) naturally have high entropy and will cause false positives. Always combine entropy with behavioral signals like I/O rate and file rename patterns.

## Prerequisites

- Python 3.8+ with `watchdog` and `psutil` libraries
- Administrative access for process monitoring and file system event capture
- Understanding of Shannon entropy and its application to file content analysis
- Windows: Sysmon installed for detailed process and file system event logging
- Linux: auditd configured for file access monitoring, or inotify-based watchers
- Baseline entropy values for common file types in the monitored environment

## Workflow

### Step 1: Establish Entropy Baselines

Calculate normal entropy ranges for files in the environment:

```
Entropy Baselines by File Type:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
File Type       Normal Entropy    Encrypted Entropy
.docx           3.5 - 6.5        7.8 - 8.0
.xlsx           4.0 - 6.8        7.8 - 8.0
.pdf            5.0 - 7.2        7.8 - 8.0
.txt            2.0 - 5.0        7.8 - 8.0
.csv            2.0 - 5.5        7.8 - 8.0
.sql            2.5 - 5.0        7.8 - 8.0
.jpg/.png       7.0 - 7.9        7.9 - 8.0 (hard to distinguish)
.zip/.7z        7.5 - 8.0        7.9 - 8.0 (hard to distinguish)

Key insight: Text-based files show the largest entropy jump when encrypted,
making them the best candidates for entropy-based detection.
```

### Step 2: Implement Real-Time Entropy Monitoring

Monitor file writes and calculate entropy of new content:

```python
import math
from collections import Counter

def shannon_entropy(data):
    """Calculate Shannon entropy of byte data (0.0 to 8.0 scale)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def is_encryption_entropy(data, threshold=7.5):
    """Check if data entropy indicates encryption."""
    entropy = shannon_entropy(data)
    return entropy >= threshold, entropy
```

### Step 3: Monitor File System I/O Patterns

Track process-level file operations for ransomware patterns:

```
Ransomware I/O Behavior Signatures:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Rapid sequential file modification:
   - >20 files modified per minute by single process
   - Read original → Write encrypted → Rename with new extension
   - Pattern: CreateFile → ReadFile → WriteFile → CloseHandle → MoveFile

2. File extension changes:
   - Original: report.docx → Encrypted: report.docx.locked
   - Many extensions changed within short time window

3. Ransom note creation:
   - Same text file (README.txt, DECRYPT.html) created in multiple directories
   - Created immediately after file encryption in each directory

4. Shadow copy deletion:
   - vssadmin.exe delete shadows /all /quiet
   - wmic.exe shadowcopy delete
   - PowerShell: Get-WmiObject Win32_Shadowcopy | Remove-WmiObject

5. Entropy spike pattern:
   - File read: entropy 3.5 (normal document)
   - File write: entropy 7.9 (encrypted content)
   - Delta > 3.0 is strong ransomware indicator
```

### Step 4: Implement Behavioral Scoring

Combine multiple signals into a composite ransomware score:

```python
def calculate_ransomware_score(process_metrics):
    """Score process behavior for ransomware likelihood (0-100)."""
    score = 0

    # High file modification rate
    files_per_min = process_metrics.get("files_modified_per_minute", 0)
    if files_per_min > 50:
        score += 30
    elif files_per_min > 20:
        score += 15

    # Entropy increase in written files
    avg_entropy_delta = process_metrics.get("avg_entropy_delta", 0)
    if avg_entropy_delta > 3.0:
        score += 30
    elif avg_entropy_delta > 2.0:
        score += 15

    # File extension changes
    extension_changes = process_metrics.get("extension_changes", 0)
    if extension_changes > 10:
        score += 20
    elif extension_changes > 3:
        score += 10

    # Ransom note creation
    if process_metrics.get("ransom_note_created", False):
        score += 20

    return min(score, 100)
```

### Step 5: Configure Automated Response Thresholds

Set detection thresholds and automated containment actions:

```
Detection Thresholds:
━━━━━━━━━━━━━━━━━━━━
Score 0-25:   INFORMATIONAL - Log only, no action
Score 25-50:  LOW - Alert SOC for investigation
Score 50-75:  HIGH - Alert SOC, suspend process, snapshot VM
Score 75-100: CRITICAL - Kill process, isolate endpoint, alert IR team

Automated Response Actions:
  - Suspend/kill the encrypting process
  - Disable network adapter to prevent lateral movement
  - Create volume shadow copy snapshot before further damage
  - Capture process memory dump for forensic analysis
  - Send SIEM alert with process details, affected files, and timeline
```

## Verification

- Test detection against known ransomware samples in an isolated sandbox environment
- Verify that entropy monitoring correctly identifies encrypted vs. compressed files
- Confirm that behavioral scoring produces low false-positive rates on normal workloads
- Validate automated response actions execute within acceptable time (under 5 seconds)
- Test with multiple ransomware families (LockBit, BlackCat, Conti) to verify coverage
- Benchmark monitoring overhead to ensure it does not degrade endpoint performance

## Key Concepts

| Term | Definition |
|------|------------|
| **Shannon Entropy** | Mathematical measure of randomness in data (0-8 for bytes); encrypted data approaches 8.0, while text files are typically 2-5 |
| **Differential Entropy** | The change in entropy between a file's original and modified content; a spike indicates encryption |
| **I/O Rate Anomaly** | Abnormally high rate of file read/write operations by a single process, characteristic of bulk encryption |
| **Behavioral Scoring** | Combining multiple weak signals (entropy, I/O rate, file renames) into a composite confidence score |
| **Entropy Evasion** | Techniques used by advanced ransomware to defeat entropy detection, such as Base64 encoding output or partial encryption |

## Tools & Systems

- **Sysmon**: Windows system monitor providing detailed file system and process events for behavioral analysis
- **watchdog (Python)**: Cross-platform file system monitoring library for real-time file change detection
- **psutil (Python)**: Process and system monitoring library for tracking per-process I/O statistics
- **Elastic Endpoint**: Commercial endpoint protection with built-in ransomware behavioral detection using canary files
- **Wazuh**: Open-source security platform with file integrity monitoring and active response capabilities

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
