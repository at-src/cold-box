---
name: cb-detecting-process-hollowing-technique
skill_id: cb-detecting-process-hollowing-technique
journal_id: CB-SKL-204
description: Cold-box analyst playbook — Detecting Process Hollowing Technique. Detect
  process hollowing (T1055.012) by analyzing memory-mapped sections, hollowed process
  indicators, and parent-child process anomalies in EDR telemetry.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- memory
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- process-hollowing
- process-injection
- edr
- t1055
- proactive-detection
cold_box_version: 2
inspired_by: detecting-process-hollowing-technique
---

# Detecting Process Hollowing Technique (cold-box)

> **Journal ID:** `CB-SKL-204` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-204`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-process-hollowing-technique")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-process-hollowing-technique")` → note **`CB-SKL-204`**
2. `log_skill(case_id, journal_id="CB-SKL-204", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-204` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating suspected fileless malware or in-memory threats
- After EDR alerts on process injection or suspicious memory operations
- When hunting for defense evasion techniques in a compromised environment
- When threat intel reports indicate process hollowing in active campaigns
- During purple team exercises validating T1055.012 detection coverage

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-204` (`cb-detecting-process-hollowing-technique`)

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

- When investigating suspected fileless malware or in-memory threats
- After EDR alerts on process injection or suspicious memory operations
- When hunting for defense evasion techniques in a compromised environment
- When threat intel reports indicate process hollowing in active campaigns
- During purple team exercises validating T1055.012 detection coverage

## Prerequisites

- EDR with memory protection monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon with Event IDs 1 (Process Create), 8 (CreateRemoteThread), 25 (ProcessTampering)
- Windows ETW providers for process hollowing (Microsoft-Windows-Kernel-Process)
- Memory forensics capabilities (Volatility, WinDbg)
- Process integrity monitoring tools

## Workflow

1. **Understand Hollowing Mechanics**: Process hollowing involves creating a legitimate process in suspended state, unmapping its memory, writing malicious code, then resuming execution.
2. **Monitor Suspended Process Creation**: Hunt for processes created with CREATE_SUSPENDED flag followed by memory writes and thread resumption.
3. **Detect Memory Section Anomalies**: Identify processes where the in-memory image differs from the on-disk binary (image mismatch).
4. **Analyze Parent-Child Process Trees**: Flag processes whose behavior does not match their binary name (e.g., svchost.exe making unusual network connections).
5. **Check Process Integrity**: Compare process memory sections against the legitimate binary on disk.
6. **Correlate with Network Activity**: Hollowed processes often establish C2 connections - correlate suspicious process behavior with network logs.
7. **Document and Contain**: Report findings, isolate affected endpoints, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1055.012 | Process Injection: Process Hollowing |
| T1055 | Process Injection (parent technique) |
| T1055.001 | DLL Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call |
| CREATE_SUSPENDED | Windows flag to create a process in suspended state |
| NtUnmapViewOfSection | API to unmap process memory sections |
| WriteProcessMemory | API to write into another process's memory |
| ResumeThread | API to resume a suspended thread |
| Image Mismatch | Process memory content differs from on-disk binary |
| Process Doppelganging | Related technique using NTFS transactions (T1055.013) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | Memory protection and hollowing detection |
| Microsoft Defender for Endpoint | ProcessTampering alerts |
| Sysmon v13+ | Event ID 25 ProcessTampering detection |
| Volatility | Memory forensics - malfind plugin |
| pe-sieve | Process memory scanner for hollowed processes |
| Hollows Hunter | Automated hollowed process detection |
| Process Hacker | Live process memory inspection |
| API Monitor | Monitor NtUnmapViewOfSection calls |

## Common Scenarios

1. **Svchost.exe Hollowing**: Malware creates svchost.exe suspended, hollows it, injects backdoor code - process appears legitimate but behaves maliciously.
2. **Explorer.exe Hollowing**: Attacker hollows explorer.exe to inherit its network permissions and trusted process context.
3. **Rundll32 Hollowing**: Malicious loader creates rundll32.exe, replaces its memory with implant code for C2 beaconing.
4. **Multi-Stage Hollowing**: Loader uses process hollowing as first stage, then performs additional injection into services.

## Output Format

```
Hunt ID: TH-HOLLOW-[DATE]-[SEQ]
Technique: T1055.012
Hollowed Process: [Process name and PID]
Original Binary: [Expected on-disk path]
Parent Process: [Parent name and PID]
Memory Mismatch: [Yes/No]
Suspicious APIs: [NtUnmapViewOfSection, WriteProcessMemory, etc.]
Network Activity: [C2 connections if any]
Host: [Hostname]
User: [Account context]
Risk Level: [Critical/High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
