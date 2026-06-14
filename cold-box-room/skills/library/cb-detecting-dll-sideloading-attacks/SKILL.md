---
name: cb-detecting-dll-sideloading-attacks
skill_id: cb-detecting-dll-sideloading-attacks
journal_id: CB-SKL-182
description: Cold-box analyst playbook — Detecting Dll Sideloading Attacks. Detect
  DLL side-loading attacks where adversaries place malicious DLLs alongside legitimate
  applications to hijack execution flow for defense evasion.
domain: cold-box
subdomain: threat-hunting
tier: adjacent
case_profiles:
- general
execution_mode: partial
artifact_platforms:
- any
host_platforms:
- linux
tags:
- threat-hunting
- mitre-attack
- dll-sideloading
- defense-evasion
- t1574
- edr
- proactive-detection
cold_box_version: 2
inspired_by: detecting-dll-sideloading-attacks
---

# Detecting Dll Sideloading Attacks (cold-box)

> **Journal ID:** `CB-SKL-182` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-182`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-detecting-dll-sideloading-attacks")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-detecting-dll-sideloading-attacks")` → note **`CB-SKL-182`**
2. `log_skill(case_id, journal_id="CB-SKL-182", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-182` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When investigating potential DLL hijacking in enterprise environments
- After EDR alerts on unsigned DLLs loaded by signed applications
- When hunting for APT persistence using legitimate application wrappers
- During incident response to identify trojanized applications
- When threat intel indicates DLL sideloading campaigns targeting specific software

## Tool map (SIFT via MCP)

**Execution mode:** `partial` — Tools mapped but some are unavailable — check `describe_sift_tool` / `list_sift_tools`.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `sigcheck` | `SIFT-183` | no | no |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `sigcheck` → `SIFT-183`

```json
{
  "tool_id": "SIFT-183",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-182] sigcheck per playbook step",
  "why": "Executing cb-detecting-dll-sideloading-attacks \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-182` (`cb-detecting-dll-sideloading-attacks`)

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

- When investigating potential DLL hijacking in enterprise environments
- After EDR alerts on unsigned DLLs loaded by signed applications
- When hunting for APT persistence using legitimate application wrappers
- During incident response to identify trojanized applications
- When threat intel indicates DLL sideloading campaigns targeting specific software

## Prerequisites

- EDR with DLL load monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon Event ID 7 (Image Loaded) with hash verification
- Application whitelisting or DLL integrity monitoring
- Software inventory of legitimate applications and expected DLL paths
- Code signing verification capabilities

## Workflow

1. **Identify Sideloading Targets**: Research known vulnerable applications that load DLLs without full path qualification (LOLBAS, DLL-sideload databases).
2. **Monitor DLL Load Events**: Query Sysmon Event ID 7 for DLL loads where the DLL path differs from the application's expected directory.
3. **Check DLL Signatures**: Flag unsigned or untrusted DLLs loaded by signed executables.
4. **Detect Path Anomalies**: Identify legitimate executables running from unusual locations (Temp, AppData, Public) that may be decoy wrappers.
5. **Hash Verification**: Compare loaded DLL hashes against known-good versions and threat intel feeds.
6. **Correlate with Process Behavior**: Check if the host process exhibits unusual behavior (network connections, child processes) after loading the suspicious DLL.
7. **Document and Remediate**: Report sideloading instances, quarantine malicious DLLs, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1574.002 | DLL Side-Loading |
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| DLL Search Order | Windows DLL loading priority path |
| Side-Loading | Placing malicious DLL where legitimate app loads it |
| Phantom DLL | DLL that legitimate apps try to load but does not exist |
| DLL Proxying | Malicious DLL forwarding calls to legitimate DLL |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Event ID 7 DLL load monitoring |
| CrowdStrike Falcon | DLL load detection with process context |
| Microsoft Defender for Endpoint | DLL load anomaly detection |
| Process Monitor | Real-time DLL load tracing |
| DLL Export Viewer | Verify DLL export functions |
| Sigcheck | Digital signature verification |
| pe-sieve | PE analysis for proxied DLLs |

## Common Scenarios

1. **Legitimate App Wrapper**: Adversary copies signed application (e.g., OneDrive updater) to temp folder alongside malicious DLL with same name as expected dependency.
2. **Phantom DLL Exploitation**: Malicious DLL placed in PATH location where legitimate app searches for non-existent DLL.
3. **DLL Proxy Loading**: Malicious version.dll proxies all exports to real version.dll while executing malicious code on DllMain.
4. **Software Update Hijack**: Attacker replaces DLL in update staging directory before legitimate updater loads it.

## Output Format

```
Hunt ID: TH-SIDELOAD-[DATE]-[SEQ]
Technique: T1574.002
Host Application: [Legitimate signed executable]
Sideloaded DLL: [Malicious DLL name and path]
Expected DLL Path: [Where DLL should legitimately be]
DLL Signed: [Yes/No]
App Location: [Expected/Anomalous]
Host: [Hostname]
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
