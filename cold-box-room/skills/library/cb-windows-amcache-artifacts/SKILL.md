---
name: cb-windows-amcache-artifacts
skill_id: cb-windows-amcache-artifacts
journal_id: CB-SKL-117
description: Cold-box analyst playbook — Windows Amcache Artifacts. Parses and analyzes
  the Windows Amcache.hve registry hive to extract evidence of program execution,
  application installation, and driver loading for digital forensics investigations.
  Uses Eric Zimmerman's AmcacheParser and Timeline Explorer
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- windows
host_platforms:
- linux
tags:
- amcache
- windows-forensics
- program-execution
- AmcacheParser
- eric-zimmerman
- timeline-analysis
- DFIR
cold_box_version: 2
inspired_by: analyzing-windows-amcache-artifacts
---

# Windows Amcache Artifacts (cold-box)

> **Journal ID:** `CB-SKL-117` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-117`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-windows-amcache-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-windows-amcache-artifacts")` → note **`CB-SKL-117`**
2. `log_skill(case_id, journal_id="CB-SKL-117", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-117` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Determining which programs have existed or executed on a Windows system during incident response
- Correlating SHA-1 hashes from Amcache against known malware databases (VirusTotal, CIRCL, MISP)
- Building an application installation and execution timeline for forensic investigations
- Identifying deleted executables that leave traces in Amcache even after file removal
- Investigating insider threats by documenting which portable or unauthorized applications were present
- Analyzing driver loading history to detect rootkits or malicious kernel modules

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `AppCompatCacheParser` | `SIFT-190` | yes | yes |
| `AmcacheParser` | `SIFT-188` | yes | yes |
| `powershell` | `SIFT-179` | no | no |
| `mount` | `SIFT-075` | no | yes |
| `PECmd` | `SIFT-221` | no | no |
| `sort` | `SIFT-020` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `AppCompatCacheParser` → `SIFT-190`

```json
{
  "tool_id": "SIFT-190",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] AppCompatCacheParser per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `AmcacheParser` → `SIFT-188`

```json
{
  "tool_id": "SIFT-188",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] AmcacheParser per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] powershell per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] mount per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `PECmd` → `SIFT-221`

```json
{
  "tool_id": "SIFT-221",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] PECmd per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `sort` → `SIFT-020`

```json
{
  "tool_id": "SIFT-020",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] sort per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] find per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-117] file per playbook step",
  "why": "Executing cb-windows-amcache-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-117` (`cb-windows-amcache-artifacts`)

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

- Determining which programs have existed or executed on a Windows system during incident response
- Correlating SHA-1 hashes from Amcache against known malware databases (VirusTotal, CIRCL, MISP)
- Building an application installation and execution timeline for forensic investigations
- Identifying deleted executables that leave traces in Amcache even after file removal
- Investigating insider threats by documenting which portable or unauthorized applications were present
- Analyzing driver loading history to detect rootkits or malicious kernel modules

**Do not use** as sole proof of program execution. Amcache proves file existence and metadata registration, but ShimCache (AppCompatCache) and Prefetch provide stronger execution evidence. Use all three artifacts together for conclusive analysis.

## Prerequisites

- A forensic image or live triage copy of `C:\Windows\appcompat\Programs\Amcache.hve` (and associated `.LOG1`, `.LOG2` transaction logs)
- Eric Zimmerman's AmcacheParser (`AmcacheParser.exe`) downloaded from https://ericzimmerman.github.io/
- Eric Zimmerman's Timeline Explorer for viewing parsed CSV output
- Optionally: Registry Explorer for manual hive inspection
- A SHA-1 whitelist of known-good executables (e.g., NSRL hashset) for filtering
- .NET 6+ runtime installed (required by current EZ tools)
- Write access to an output directory for CSV results

## Workflow

### Step 1: Acquire the Amcache.hve File

Extract the Amcache hive from a forensic image or live system:

```powershell
# From a live system (requires elevated privileges and raw copy tool)
# Amcache.hve is locked by the system; use a raw disk copy tool
# Option A: FTK Imager - mount image and navigate to:
# C:\Windows\appcompat\Programs\Amcache.hve
# Also collect: Amcache.hve.LOG1, Amcache.hve.LOG2

# Option B: Using KAPE for automated triage collection
kape.exe --tsource C: --tdest D:\Evidence\%m --target Amcache

# Option C: From a mounted forensic image (E: = mounted image)
copy "E:\Windows\appcompat\Programs\Amcache.hve" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG1" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG2" D:\Evidence\
```

Always collect the transaction log files (`.LOG1`, `.LOG2`) alongside the hive. AmcacheParser replays uncommitted transactions from these logs to recover the most complete data.

### Step 2: Parse Amcache with AmcacheParser

Run AmcacheParser against the acquired hive:

```powershell
# Basic parsing with CSV output
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output"

# Parse with a SHA-1 whitelist to exclude known-good entries (NSRL)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -w "D:\Whitelists\nsrl_sha1.txt" --csv "D:\Evidence\Output"

# Parse with a SHA-1 inclusion list (only show matches against known-bad hashes)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -b "D:\IOCs\malware_sha1.txt" --csv "D:\Evidence\Output"

# Include deleted entries with high-precision timestamps
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output" -i --mp
```

AmcacheParser produces multiple CSV files in the output directory:

| Output File | Contents |
|-------------|----------|
| `Amcache_AssociatedFileEntries.csv` | File entries with SHA-1 hashes, paths, sizes, and timestamps |
| `Amcache_UnassociatedFileEntries.csv` | Orphaned file entries from older Amcache format |
| `Amcache_ProgramEntries.csv` | Installed program metadata (name, publisher, version, install date) |
| `Amcache_DeviceContainers.csv` | USB and device connection history |
| `Amcache_DevicePnps.csv` | Plug-and-Play device driver information |
| `Amcache_DriverBinaries.csv` | Loaded driver binaries with paths and hashes |

### Step 3: Analyze File Entries for Suspicious Programs

Open the `AssociatedFileEntries.csv` in Timeline Explorer and examine key columns:

```
Key columns to review:
- ProgramId          : Links file to its parent program entry
- SHA1               : Hash for threat intel lookups
- FullPath           : Original file location on disk
- FileSize           : Size of the executable
- FileKeyLastWriteTimestamp : When the Amcache entry was last updated
- Name               : File name
- Publisher           : Code signing publisher (blank = unsigned)
- BinProductVersion  : Version string from the PE header
- LinkDate           : PE compilation timestamp (useful for detecting timestomping)
```

Filter for suspicious indicators:

```
# In Timeline Explorer, apply these filters:

# 1. Find unsigned executables (potentially malicious)
Publisher column = (empty)

# 2. Find executables from suspicious paths
FullPath contains: \temp\, \appdata\, \downloads\, \public\, \programdata\

# 3. Find executables with recent timestamps during incident window
FileKeyLastWriteTimestamp between: 2026-03-15 00:00:00 and 2026-03-16 00:00:00

# 4. Find executables with suspicious compilation dates (timestomping)
LinkDate year < 2015 AND FileKeyLastWriteTimestamp year = 2026
```

### Step 4: Correlate SHA-1 Hashes with Threat Intelligence

Extract SHA-1 hashes and check against malware databases:

```powershell
# Extract unique SHA-1 hashes from the parsed output
# Using PowerShell to extract the SHA1 column
Import-Csv "D:\Evidence\Output\Amcache_AssociatedFileEntries.csv" |
  Select-Object -ExpandProperty SHA1 -Unique |
  Where-Object { $_ -ne "" } |
  Out-File "D:\Evidence\Output\extracted_hashes.txt"

# Check hashes against VirusTotal using vt-cli
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    vt file $hash --format json | Select-Object -Property meaningful_name, last_analysis_stats
}

# Check hashes against CIRCL hashlookup
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha1/$hash"
}

# Cross-reference with NSRL to identify known-good vs. unknown
# Unknown hashes that are not in NSRL warrant closer investigation
```

### Step 5: Analyze Program Entries for Unauthorized Installations

Review the `ProgramEntries.csv` for software the attacker may have installed:

```
Key columns in ProgramEntries:
- ProgramName        : Display name of installed application
- ProgramVersion     : Version string
- Publisher          : Software publisher
- InstallDate        : When the program was installed
- Source             : Installation source (msi, exe, etc.)
- UninstallKey       : Registry uninstall path
- PathsList         : Installation directories
```

Look for:
- Remote access tools (AnyDesk, TeamViewer, ngrok, Chisel)
- Hacking tools (Mimikatz, PsExec, Cobalt Strike)
- Tunneling utilities (plink, socat, WireGuard)
- Programs installed during the incident window
- Programs installed to non-standard locations

### Step 6: Analyze Driver Binaries for Rootkit Evidence

Review the `DriverBinaries.csv` for suspicious loaded drivers:

```
Key columns in DriverBinaries:
- DriverName         : Name of the driver
- DriverInBox        : Whether it shipped with Windows (false = third-party)
- DriverSigned       : Whether the driver has a valid signature
- DriverTimeStamp    : Compilation timestamp
- Product            : Product associated with the driver
- ProductVersion     : Driver version
- SHA1               : Hash of the driver binary
```

Filter for `DriverInBox = false` and `DriverSigned = false` to find unsigned third-party drivers that may be rootkits or vulnerable drivers used in BYOVD (Bring Your Own Vulnerable Driver) attacks.

### Step 7: Build a Timeline from Amcache Data

Combine Amcache data with other artifacts for a comprehensive timeline:

```powershell
# Merge Amcache CSV with other EZ Tools output using Timeline Explorer
# Load the following CSVs into Timeline Explorer:
# - Amcache_AssociatedFileEntries.csv (file evidence)
# - Amcache_ProgramEntries.csv (install evidence)
# - Prefetch output from PECmd.exe (execution evidence)
# - ShimCache output from AppCompatCacheParser.exe (execution evidence)

# Sort all entries by timestamp to reconstruct the attack sequence
# Timeline Explorer supports multi-file loading and column-based sorting

# Export the combined timeline
# File > Save to CSV > combined_timeline.csv
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Amcache.hve** | A Windows registry hive at `C:\Windows\appcompat\Programs\Amcache.hve` that stores metadata about applications, files, and drivers for application compatibility purposes |
| **Associated File Entry** | An Amcache record linked to a specific program installation, containing file path, size, hash, and timestamps |
| **Unassociated File Entry** | An orphaned Amcache record from an older format that is not linked to a program entry; common on Windows 7/8 systems |
| **Program Entry** | Amcache record containing installation metadata: program name, version, publisher, install date, and uninstall key |
| **SHA-1 Hash** | Cryptographic hash stored in Amcache for each registered file, enabling malware identification through threat intelligence lookups |
| **LinkDate** | The PE compilation timestamp embedded in the executable header; discrepancy with file system timestamps may indicate timestomping |
| **Transaction Logs** | `.LOG1` and `.LOG2` files containing uncommitted registry transactions that AmcacheParser replays for complete data recovery |
| **NSRL (National Software Reference Library)** | NIST-maintained database of SHA-1 hashes for known commercial software, used as a whitelist to filter benign entries |

## Verification

- [ ] Amcache.hve and transaction logs (LOG1, LOG2) were collected from the forensic image
- [ ] AmcacheParser produced all expected CSV output files without errors
- [ ] SHA-1 hashes were extracted and checked against VirusTotal or CIRCL hashlookup
- [ ] Unsigned executables in suspicious paths have been flagged for further analysis
- [ ] Program entries show all software installations within the incident window
- [ ] Driver binaries have been checked for unsigned or out-of-box entries
- [ ] LinkDate vs. FileKeyLastWriteTimestamp comparison has been performed to detect timestomping
- [ ] Amcache findings are correlated with Prefetch and ShimCache for execution confirmation
- [ ] Final timeline integrates Amcache data with other forensic artifacts

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
