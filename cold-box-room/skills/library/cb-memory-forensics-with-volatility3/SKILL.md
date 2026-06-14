---
name: cb-memory-forensics-with-volatility3
skill_id: cb-memory-forensics-with-volatility3
journal_id: CB-SKL-086
description: Cold-box analyst playbook — Memory Forensics With Volatility3. Analyze
  volatile memory dumps using Volatility 3 to extract running processes, network connections,
  loaded modules, and evidence of malicious activity.
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
- forensics
- memory-forensics
- volatility
- ram-analysis
- malware-detection
- incident-response
cold_box_version: 2
inspired_by: performing-memory-forensics-with-volatility3
---

# Memory Forensics With Volatility3 (cold-box)

> **Journal ID:** `CB-SKL-086` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-086`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-memory-forensics-with-volatility3")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-memory-forensics-with-volatility3")` → note **`CB-SKL-086`**
2. `log_skill(case_id, journal_id="CB-SKL-086", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-086` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When analyzing a RAM dump from a compromised or suspect system
- During incident response to identify running malware, injected code, or rootkits
- When you need to extract credentials, encryption keys, or network connections from memory
- For detecting process hollowing, DLL injection, or hidden processes
- When disk-based forensics alone is insufficient and volatile data is critical

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sha256sum` | `SIFT-018` | yes | yes |
| `strings` | `SIFT-044` | yes | yes |
| `pslist` | `SIFT-182` | no | no |
| `unzip` | `SIFT-004` | yes | yes |
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `diff` | `SIFT-007` | yes | yes |
| `yara` | `SIFT-045` | no | no |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `awk` | `SIFT-005` | yes | yes |
| `vol` | `SIFT-173` | no | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] powershell per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] sha256sum per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] strings per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `pslist` → `SIFT-182`

```json
{
  "tool_id": "SIFT-182",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] pslist per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `unzip` → `SIFT-004`

```json
{
  "tool_id": "SIFT-004",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] unzip per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] sort per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] grep per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-086] find per playbook step",
  "why": "Executing cb-memory-forensics-with-volatility3 \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-086` (`cb-memory-forensics-with-volatility3`)

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
- When analyzing a RAM dump from a compromised or suspect system
- During incident response to identify running malware, injected code, or rootkits
- When you need to extract credentials, encryption keys, or network connections from memory
- For detecting process hollowing, DLL injection, or hidden processes
- When disk-based forensics alone is insufficient and volatile data is critical

## Prerequisites
- Python 3.7+ installed
- Volatility 3 framework installed (`pip install volatility3`)
- Memory dump in raw, ELF, or crash dump format
- Appropriate symbol tables (ISF files) for the target OS version
- Sufficient disk space for analysis output (2-3x memory dump size)
- Optional: YARA rules for malware scanning in memory

## Workflow

### Step 1: Acquire Memory Dump and Install Volatility 3

```bash
# Install Volatility 3
pip install volatility3

# Or install from source for latest features
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .

# Download Windows symbol tables (ISF packs)
# Place in volatility3/symbols/ directory
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d /opt/volatility3/volatility3/symbols/

# Download Linux and Mac symbol packs
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip

# Memory acquisition tools (for live systems):
# Windows: winpmem, DumpIt, FTK Imager
# Linux: LiME (Linux Memory Extractor)
sudo insmod lime-$(uname -r).ko "path=/cases/memory/linux_mem.lime format=lime"

# Verify the memory dump
file /cases/case-2024-001/memory/memory.raw
ls -lh /cases/case-2024-001/memory/memory.raw
```

### Step 2: Identify the Operating System Profile

```bash
# Run banners plugin to identify the OS
vol -f /cases/case-2024-001/memory/memory.raw banners

# For Windows, identify the OS version
vol -f /cases/case-2024-001/memory/memory.raw windows.info

# Output example:
# Variable        Value
# Kernel Base     0xf8047e200000
# DTB             0x1ad000
# Symbols         ntkrnlmp.pdb/GUID
# Is64Bit         True
# IsPAE           False
# primary layer   Intel32e
# KdVersionBlock  0xf8047ee232c0
# Major/Minor     15.19041
# Machine Type    34404
# KeNumberProcessors 4
# SystemTime      2024-01-18 14:32:15 UTC
# NtBuildLab      19041.1.amd64fre.vb_release.191206-1406
# NtProductType   NtProductWinNt
# NtSystemRoot    C:\WINDOWS
# PE MajorOperatingSystemVersion 10
# PE MinorOperatingSystemVersion 0

# For Linux memory dumps
vol -f /cases/case-2024-001/memory/linux_mem.lime linux.info
```

### Step 3: Enumerate Processes and Detect Anomalies

```bash
# List all running processes
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | tee /cases/case-2024-001/analysis/pslist.txt

# Show process tree (parent-child relationships)
vol -f /cases/case-2024-001/memory/memory.raw windows.pstree | tee /cases/case-2024-001/analysis/pstree.txt

# Detect hidden processes using cross-view analysis
vol -f /cases/case-2024-001/memory/memory.raw windows.psscan | tee /cases/case-2024-001/analysis/psscan.txt

# Compare pslist vs psscan to find hidden processes
diff <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort) \
     <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort)

# List DLLs loaded by a suspicious process (PID 4532)
vol -f /cases/case-2024-001/memory/memory.raw windows.dlllist --pid 4532

# Check for process hollowing and injection
vol -f /cases/case-2024-001/memory/memory.raw windows.malfind | tee /cases/case-2024-001/analysis/malfind.txt

# Dump suspicious process memory for further analysis
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 4532 --dump \
   -o /cases/case-2024-001/analysis/dumps/
```

### Step 4: Analyze Network Connections and Registry

```bash
# List active network connections
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | tee /cases/case-2024-001/analysis/netscan.txt

# Filter for established connections
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep ESTABLISHED

# Filter for listening ports
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep LISTENING

# Extract network connections with process mapping
vol -f /cases/case-2024-001/memory/memory.raw windows.netstat | tee /cases/case-2024-001/analysis/netstat.txt

# Dump registry hives from memory
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.hivelist

# Extract specific registry keys
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.printkey \
   --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Check services
vol -f /cases/case-2024-001/memory/memory.raw windows.svcscan | tee /cases/case-2024-001/analysis/services.txt
```

### Step 5: Extract Credentials and Sensitive Data

```bash
# Dump cached credentials (hashdump)
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump | tee /cases/case-2024-001/analysis/hashes.txt

# Extract LSA secrets
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump

# Dump cached domain credentials
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump

# Search for plaintext strings in process memory
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 4532 \
   | grep -iE '(password|credential|token|api.key)'

# Extract command history from cmd.exe/powershell
vol -f /cases/case-2024-001/memory/memory.raw windows.cmdline | tee /cases/case-2024-001/analysis/cmdline.txt

# Extract environment variables
vol -f /cases/case-2024-001/memory/memory.raw windows.envars --pid 4532
```

### Step 6: Scan for Malware with YARA Rules

```bash
# Scan memory with YARA rules
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/malware_index.yar | tee /cases/case-2024-001/analysis/yara_hits.txt

# Scan specific process memory
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/apt_rules.yar --pid 4532

# Check loaded kernel modules for rootkits
vol -f /cases/case-2024-001/memory/memory.raw windows.modules | tee /cases/case-2024-001/analysis/modules.txt

# Detect unlinked/hidden modules
vol -f /cases/case-2024-001/memory/memory.raw windows.modscan | tee /cases/case-2024-001/analysis/modscan.txt

# Check for SSDT hooks (System Service Descriptor Table)
vol -f /cases/case-2024-001/memory/memory.raw windows.ssdt | grep -v "ntoskrnl\|win32k"

# Dump a suspicious executable from memory
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 4532 \
   -o /cases/case-2024-001/analysis/extracted/
```

### Step 7: Compile Findings into a Report

```bash
# Generate comprehensive analysis summary
echo "=== MEMORY FORENSICS REPORT ===" > /cases/case-2024-001/analysis/memory_report.txt
echo "Image: memory.raw" >> /cases/case-2024-001/analysis/memory_report.txt
echo "OS: Windows 10 Build 19041" >> /cases/case-2024-001/analysis/memory_report.txt
echo "" >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Suspicious Processes ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/malfind.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- Network Connections ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/netscan.txt >> /cases/case-2024-001/analysis/memory_report.txt

echo "--- YARA Matches ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/yara_hits.txt >> /cases/case-2024-001/analysis/memory_report.txt

# Calculate hash of the memory dump for integrity
sha256sum /cases/case-2024-001/memory/memory.raw >> /cases/case-2024-001/analysis/memory_report.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Volatile data | Information that exists only in RAM and is lost when power is removed |
| Process hollowing | Technique where malware replaces legitimate process memory with malicious code |
| DLL injection | Loading unauthorized DLLs into a running process address space |
| EPROCESS | Windows kernel structure representing a process; basis for process listing |
| Pool scanning | Searching memory for kernel object signatures to find hidden artifacts |
| VAD (Virtual Address Descriptor) | Memory management structure tracking process virtual memory regions |
| ISF (Intermediate Symbol Format) | Volatility 3 symbol table format for OS-specific structure definitions |
| Malfind | Plugin detecting injected code by examining VAD permissions and content |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Volatility 3 | Primary open-source memory forensics framework |
| LiME | Linux Memory Extractor for acquiring Linux RAM dumps |
| WinPmem | Windows physical memory acquisition driver |
| DumpIt | Comae one-click Windows memory dump utility |
| YARA | Pattern matching engine for malware signature scanning |
| Rekall | Alternative memory forensics framework (Google) |
| MemProcFS | Memory process file system for memory analysis |
| strings | Extract printable strings from binary memory dumps |

## Common Scenarios

**Scenario 1: Active Malware Investigation**
Acquire memory with DumpIt, run pslist/pstree to identify suspicious processes, use malfind to detect injected code in svchost.exe, dump the injected memory segment, scan with YARA rules identifying Cobalt Strike beacon, extract C2 IP from netscan, correlate with network logs.

**Scenario 2: Credential Theft After Breach**
Run hashdump and lsadump to extract cached credentials, identify mimikatz execution in cmdline output, check for lsass.exe memory dumps in filesystem artifacts, correlate with lateral movement evidence in network connections.

**Scenario 3: Rootkit Detection**
Compare pslist (uses EPROCESS linked list) with psscan (pool scanning) to find unlinked processes, check modules vs modscan for hidden kernel drivers, examine SSDT for hooks redirecting system calls, dump suspicious modules for static analysis.

**Scenario 4: Ransomware Incident Recovery**
Extract encryption keys from ransomware process memory before system shutdown, identify the ransomware variant using YARA, find the initial execution point through command line artifacts, map lateral movement via network connections.

## Output Format

```
Memory Forensics Analysis:
  Image:            memory.raw (16 GB)
  OS Identified:    Windows 10 x64 Build 19041
  Capture Time:     2024-01-18 14:32:15 UTC

  Process Analysis:
    Total Processes:    87
    Hidden Processes:   2 (PIDs: 4532, 6128)
    Injected Processes: 3 (malfind detections)
    Suspicious:         svchost.exe (PID 4532) - injected code at 0x7FFE0000

  Network Connections:
    Total:        45
    Established:  12
    Suspicious:   3 (C2 connections to 185.xx.xx.xx:443)

  Credentials Found:
    NTLM Hashes:      4 accounts
    Cached Creds:      2 domain accounts

  YARA Matches:
    CobaltStrike_Beacon:  PID 4532 (3 hits)
    Mimikatz_Memory:      PID 6128 (1 hit)

  Extracted Artifacts:   15 files dumped to /analysis/extracted/
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
