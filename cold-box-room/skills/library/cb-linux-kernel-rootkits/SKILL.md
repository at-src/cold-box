---
name: cb-linux-kernel-rootkits
skill_id: cb-linux-kernel-rootkits
journal_id: CB-SKL-071
description: 'Cold-box analyst playbook — Linux Kernel Rootkits. Detect kernel-level
  rootkits in Linux memory dumps using Volatility3 linux plugins (check_syscall, lsmod,
  hidden_modules), rkhunter system scanning, and /proc vs /sys discrepancy analysis
  to identify hooked syscalls, hidden kernel modules, '
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- rootkit
- linux
- kernel
- volatility3
- memory-forensics
- malware-analysis
- rkhunter
- forensics
cold_box_version: 2
inspired_by: analyzing-linux-kernel-rootkits
---

# Linux Kernel Rootkits (cold-box)

> **Journal ID:** `CB-SKL-071` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-071`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-linux-kernel-rootkits")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-linux-kernel-rootkits")` → note **`CB-SKL-071`**
2. `log_skill(case_id, journal_id="CB-SKL-071", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-071` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating security incidents that require analyzing linux kernel rootkits
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `ls` → `SIFT-014`

```json
{
  "tool_id": "SIFT-014",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-071] ls per playbook step",
  "why": "Executing cb-linux-kernel-rootkits \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-071` (`cb-linux-kernel-rootkits`)

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

Linux kernel rootkits operate at ring 0, modifying kernel data structures to hide processes, files, network connections, and kernel modules from userspace tools. Detection requires either memory forensics (analyzing physical memory dumps with Volatility3) or cross-view analysis (comparing /proc, /sys, and kernel data structures for inconsistencies). This skill covers using Volatility3 Linux plugins to detect syscall table hooks, hidden kernel modules, and modified function pointers, supplemented by live system scanning with rkhunter and chkrootkit.


## When to Use

- When investigating security incidents that require analyzing linux kernel rootkits
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Volatility3 installed (pip install volatility3)
- Linux memory dump (acquired via LiME, AVML, or /proc/kcore)
- Volatility3 Linux symbol table (ISF) matching the target kernel version
- rkhunter and chkrootkit for live system scanning
- Reference known-good kernel image for comparison

## Steps

### Step 1: Acquire Memory Dump
Capture Linux physical memory using LiME kernel module or AVML for cloud instances.

### Step 2: Analyze with Volatility3
Run linux.check_syscall, linux.lsmod, linux.hidden_modules, and linux.check_idt plugins to detect rootkit artifacts.

### Step 3: Cross-View Analysis
Compare module lists from /proc/modules, lsmod, and /sys/module to identify modules hidden from one view but present in another.

### Step 4: Live System Scanning
Run rkhunter and chkrootkit to detect known rootkit signatures, suspicious files, and modified system binaries.

## Expected Output

JSON report containing detected syscall hooks, hidden kernel modules, modified IDT entries, suspicious /proc discrepancies, and rkhunter findings.

## Example Output

```text
$ sudo python3 rootkit_analyzer.py --memory /evidence/linux-mem.lime --profile Ubuntu2204

Linux Kernel Rootkit Analysis Report
=====================================
Memory Image: /evidence/linux-mem.lime
Kernel Version: 5.15.0-91-generic (Ubuntu 22.04 LTS)
Analysis Time: 2024-01-18 09:15:32 UTC

[+] Scanning syscall table for hooks...
    Syscall Table Base: 0xffffffff82200300
    Total syscalls checked: 449

    HOOKED SYSCALLS DETECTED:
    ┌─────────┬──────────────────┬──────────────────────┬──────────────────────┐
    │ NR      │ Syscall          │ Expected Address     │ Current Address      │
    ├─────────┼──────────────────┼──────────────────────┼──────────────────────┤
    │ 0       │ sys_read         │ 0xffffffff8139a0e0   │ 0xffffffffc0a12000   │
    │ 2       │ sys_open         │ 0xffffffff8139b340   │ 0xffffffffc0a12180   │
    │ 78      │ sys_getdents64   │ 0xffffffff813f5210   │ 0xffffffffc0a12300   │
    │ 62      │ sys_kill         │ 0xffffffff8110c4a0   │ 0xffffffffc0a12480   │
    └─────────┴──────────────────┴──────────────────────┴──────────────────────┘
    WARNING: 4 syscall hooks detected - rootkit behavior confirmed

[+] Checking for hidden kernel modules...
    Loaded modules (lsmod):         147
    Modules in kobject list:        149
    HIDDEN MODULES:
      - "netfilter_helper" at 0xffffffffc0a10000 (size: 12288)
      - "kworker_sched"    at 0xffffffffc0a14000 (size: 8192)

[+] Scanning /proc for discrepancies...
    Processes in task_struct list: 234
    Processes visible in /proc:   231
    HIDDEN PROCESSES:
      - PID 31337  cmd: "[kworker/0:3]"   (disguised as kernel thread)
      - PID 31442  cmd: "rsyslogd"         (fake, real rsyslogd is PID 892)
      - PID 31500  cmd: ""                 (unnamed process)

[+] Checking IDT entries...
    IDT entries scanned: 256
    Modified entries: 0 (clean)

[+] Running rkhunter scan...
    Checking for known rootkits:        68 variants checked
    Diamorphine rootkit:                WARNING - signatures match
    System binary checks:
      /usr/bin/ps:     MODIFIED (SHA-256 mismatch)
      /usr/bin/netstat: MODIFIED (SHA-256 mismatch)
      /usr/bin/ls:     MODIFIED (SHA-256 mismatch)
      /usr/sbin/ss:    OK

[+] Network analysis...
    Hidden connections (not in /proc/net/tcp):
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:4443 (PID 31337)
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:8080 (PID 31442)

Summary:
  Rootkit Type:         Loadable Kernel Module (LKM)
  Probable Family:      Diamorphine variant
  Syscall Hooks:        4 (read, open, getdents64, kill)
  Hidden Modules:       2
  Hidden Processes:     3
  Hidden Connections:   2 (C2: 198.51.100.47)
  Modified Binaries:    3 (/usr/bin/ps, netstat, ls)
  Risk Level:           CRITICAL
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
