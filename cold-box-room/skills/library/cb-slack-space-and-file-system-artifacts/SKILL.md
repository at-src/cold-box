---
name: cb-slack-space-and-file-system-artifacts
skill_id: cb-slack-space-and-file-system-artifacts
journal_id: CB-SKL-107
description: Cold-box analyst playbook — Slack Space And File System Artifacts. Examine
  file system slack space, MFT entries, USN journal, and alternate data streams to
  recover hidden data and reconstruct file activity on NTFS volumes.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- forensics
- slack-space
- ntfs
- mft
- usn-journal
- alternate-data-streams
- file-system-analysis
cold_box_version: 2
inspired_by: analyzing-slack-space-and-file-system-artifacts
---

# Slack Space And File System Artifacts (cold-box)

> **Journal ID:** `CB-SKL-107` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-107`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-slack-space-and-file-system-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-slack-space-and-file-system-artifacts")` → note **`CB-SKL-107`**
2. `log_skill(case_id, journal_id="CB-SKL-107", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-107` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When searching for hidden or residual data in file system slack space
- For analyzing NTFS Master File Table (MFT) entries for deleted file metadata
- When reconstructing file operations from the USN Change Journal
- For detecting Alternate Data Streams (ADS) used to hide data or malware
- During deep forensic analysis requiring examination beyond standard file recovery

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `img_stat` | `SIFT-154` | yes | yes |
| `bulk_extractor` | `SIFT-032` | yes | yes |
| `analyzemft` | `SIFT-189` | yes | yes |
| `foremost` | `SIFT-040` | yes | yes |
| `MFTECmd` | `SIFT-217` | yes | yes |
| `strings` | `SIFT-044` | yes | yes |
| `blkstat` | `SIFT-139` | yes | yes |
| `fsstat` | `SIFT-149` | yes | yes |
| `blkls` | `SIFT-138` | yes | yes |
| `istat` | `SIFT-155` | no | yes |
| `grep` | `SIFT-010` | yes | yes |
| `icat` | `SIFT-151` | no | yes |
| `find` | `SIFT-009` | yes | yes |
| `mmls` | `SIFT-160` | no | yes |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `awk` | `SIFT-005` | yes | yes |
| `fls` | `SIFT-148` | yes | yes |
| `dd` | `SIFT-034` | no | yes |
| `tr` | `SIFT-024` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] img_stat per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `bulk_extractor` → `SIFT-032`

```json
{
  "tool_id": "SIFT-032",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] bulk_extractor per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `analyzemft` → `SIFT-189`

```json
{
  "tool_id": "SIFT-189",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] analyzemft per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `foremost` → `SIFT-040`

```json
{
  "tool_id": "SIFT-040",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] foremost per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `MFTECmd` → `SIFT-217`

```json
{
  "tool_id": "SIFT-217",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] MFTECmd per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] strings per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `blkstat` → `SIFT-139`

```json
{
  "tool_id": "SIFT-139",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] blkstat per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `fsstat` → `SIFT-149`

```json
{
  "tool_id": "SIFT-149",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-107] fsstat per playbook step",
  "why": "Executing cb-slack-space-and-file-system-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-107` (`cb-slack-space-and-file-system-artifacts`)

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
- When searching for hidden or residual data in file system slack space
- For analyzing NTFS Master File Table (MFT) entries for deleted file metadata
- When reconstructing file operations from the USN Change Journal
- For detecting Alternate Data Streams (ADS) used to hide data or malware
- During deep forensic analysis requiring examination beyond standard file recovery

## Prerequisites
- Forensic disk image with NTFS file system
- The Sleuth Kit (TSK) tools: istat, icat, fls, blkls, blkstat
- MFTECmd (Eric Zimmerman) for MFT parsing
- MFTExplorer for interactive MFT analysis
- Understanding of NTFS structures (MFT, $UsnJrnl, $LogFile, ADS)
- Python with analyzeMFT or mft library for automated parsing

## Workflow

### Step 1: Identify and Extract NTFS File System Artifacts

```bash
# Determine partition layout
mmls /cases/case-2024-001/images/evidence.dd

# Extract key NTFS system files
# $MFT - Master File Table
icat -o 2048 /cases/case-2024-001/images/evidence.dd 0 > /cases/case-2024-001/ntfs/MFT

# $UsnJrnl:$J - USN Change Journal
icat -o 2048 /cases/case-2024-001/images/evidence.dd 62-128 > /cases/case-2024-001/ntfs/UsnJrnl_J

# $LogFile - Transaction log
icat -o 2048 /cases/case-2024-001/images/evidence.dd 2 > /cases/case-2024-001/ntfs/LogFile

# Extract all slack space from the volume
blkls -s -o 2048 /cases/case-2024-001/images/evidence.dd > /cases/case-2024-001/ntfs/slack_space.raw

# Get file system information
fsstat -o 2048 /cases/case-2024-001/images/evidence.dd | tee /cases/case-2024-001/ntfs/fs_info.txt
```

### Step 2: Analyze the Master File Table (MFT)

```bash
# Parse MFT with MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "C:\cases\ntfs\MFT" --csv "C:\cases\analysis\" --csvf mft_analysis.csv

# Parse with analyzeMFT (Python)
pip install analyzeMFT

analyzeMFT.py -f /cases/case-2024-001/ntfs/MFT \
   -o /cases/case-2024-001/analysis/mft_analysis.csv \
   -c

# Custom MFT analysis with Python
python3 << 'PYEOF'
from mft import PyMft
import csv

mft = PyMft(open('/cases/case-2024-001/ntfs/MFT', 'rb').read())

deleted_files = []
suspicious_files = []

for entry in mft.entries():
    if entry is None:
        continue

    filename = entry.get_filename()
    if filename is None:
        continue

    is_deleted = not entry.is_active()
    is_directory = entry.is_directory()
    created = entry.get_created_timestamp()
    modified = entry.get_modified_timestamp()
    mft_modified = entry.get_mft_modified_timestamp()
    size = entry.get_file_size()

    # Flag deleted files for recovery
    if is_deleted and not is_directory and size > 0:
        deleted_files.append({
            'filename': filename,
            'size': size,
            'created': str(created),
            'modified': str(modified),
            'entry_number': entry.entry_number
        })

    # Detect timestomping (MFT modified time != $SI modified time)
    si_modified = entry.get_si_modified_timestamp()
    fn_modified = entry.get_fn_modified_timestamp()
    if si_modified and fn_modified:
        if abs((si_modified - fn_modified).total_seconds()) > 86400:  # >1 day difference
            suspicious_files.append({
                'filename': filename,
                'si_modified': str(si_modified),
                'fn_modified': str(fn_modified),
                'delta': str(si_modified - fn_modified)
            })

print(f"=== DELETED FILES (recoverable metadata) ===")
print(f"Total: {len(deleted_files)}")
for f in deleted_files[:20]:
    print(f"  [{f['modified']}] {f['filename']} ({f['size']} bytes)")

print(f"\n=== POTENTIAL TIMESTOMPING ===")
print(f"Total suspicious: {len(suspicious_files)}")
for f in suspicious_files[:10]:
    print(f"  {f['filename']}: $SI={f['si_modified']}, $FN={f['fn_modified']} (delta: {f['delta']})")
PYEOF
```

### Step 3: Analyze Slack Space for Hidden Data

```bash
# Search slack space for strings
strings -a /cases/case-2024-001/ntfs/slack_space.raw > /cases/case-2024-001/analysis/slack_strings.txt

# Search for specific patterns in slack space
grep -iab "password\|secret\|confidential\|credit.card\|ssn" \
   /cases/case-2024-001/ntfs/slack_space.raw > /cases/case-2024-001/analysis/slack_keywords.txt

# Analyze individual file slack
python3 << 'PYEOF'
import struct

# File slack consists of:
# 1. RAM slack: bytes between file end and next sector boundary (filled with RAM content or zeros)
# 2. Drive slack: remaining sectors in the cluster after the last file sector

# Analyze slack for specific MFT entries
# Using Sleuth Kit to get file slack for a specific file
import subprocess

# Get file details
result = subprocess.run(
    ['istat', '-o', '2048', '/cases/case-2024-001/images/evidence.dd', '14523'],
    capture_output=True, text=True
)
print(result.stdout)

# The output shows data runs - the last cluster may contain slack data
# Calculate slack size: (allocated_size - file_size) bytes
PYEOF

# Search for file signatures in slack space (embedded files)
foremost -t jpg,pdf,zip -i /cases/case-2024-001/ntfs/slack_space.raw \
   -o /cases/case-2024-001/carved/slack_carved/

# Use bulk_extractor to find structured data in slack
bulk_extractor -o /cases/case-2024-001/analysis/bulk_extract/ \
   /cases/case-2024-001/ntfs/slack_space.raw
```

### Step 4: Parse the USN Change Journal

```bash
# Parse USN Journal with MFTECmd
MFTECmd.exe -f "C:\cases\ntfs\UsnJrnl_J" --csv "C:\cases\analysis\" --csvf usn_journal.csv

# Python USN Journal parsing
pip install pyusn

python3 << 'PYEOF'
import struct
import csv
from datetime import datetime, timedelta

def parse_usn_record(data, offset):
    """Parse a single USN_RECORD_V2."""
    if offset + 8 > len(data):
        return None, offset

    record_len = struct.unpack_from('<I', data, offset)[0]
    if record_len < 56 or record_len > 65536 or offset + record_len > len(data):
        return None, offset + 8

    major_ver = struct.unpack_from('<H', data, offset + 4)[0]
    if major_ver != 2:
        return None, offset + record_len

    mft_ref = struct.unpack_from('<Q', data, offset + 8)[0] & 0xFFFFFFFFFFFF
    parent_ref = struct.unpack_from('<Q', data, offset + 16)[0] & 0xFFFFFFFFFFFF
    usn = struct.unpack_from('<Q', data, offset + 24)[0]
    timestamp = struct.unpack_from('<Q', data, offset + 32)[0]
    reason = struct.unpack_from('<I', data, offset + 40)[0]
    source_info = struct.unpack_from('<I', data, offset + 44)[0]
    security_id = struct.unpack_from('<I', data, offset + 48)[0]
    file_attrs = struct.unpack_from('<I', data, offset + 52)[0]
    filename_len = struct.unpack_from('<H', data, offset + 56)[0]
    filename_off = struct.unpack_from('<H', data, offset + 58)[0]

    name = data[offset + filename_off:offset + filename_off + filename_len].decode('utf-16-le', errors='ignore')

    # Convert Windows FILETIME to datetime
    ts = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)

    # Decode reason flags
    reasons = []
    reason_flags = {
        0x01: 'DATA_OVERWRITE', 0x02: 'DATA_EXTEND', 0x04: 'DATA_TRUNCATION',
        0x10: 'NAMED_DATA_OVERWRITE', 0x20: 'NAMED_DATA_EXTEND',
        0x100: 'FILE_CREATE', 0x200: 'FILE_DELETE', 0x400: 'EA_CHANGE',
        0x800: 'SECURITY_CHANGE', 0x1000: 'RENAME_OLD_NAME', 0x2000: 'RENAME_NEW_NAME',
        0x4000: 'INDEXABLE_CHANGE', 0x8000: 'BASIC_INFO_CHANGE',
        0x10000: 'HARD_LINK_CHANGE', 0x20000: 'COMPRESSION_CHANGE',
        0x40000: 'ENCRYPTION_CHANGE', 0x80000: 'OBJECT_ID_CHANGE',
        0x100000: 'REPARSE_POINT_CHANGE', 0x200000: 'STREAM_CHANGE',
        0x80000000: 'CLOSE'
    }
    for flag, desc in reason_flags.items():
        if reason & flag:
            reasons.append(desc)

    record = {
        'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
        'filename': name,
        'mft_entry': mft_ref,
        'parent_entry': parent_ref,
        'reasons': '|'.join(reasons),
        'usn': usn
    }

    return record, offset + record_len

# Parse the journal
with open('/cases/case-2024-001/ntfs/UsnJrnl_J', 'rb') as f:
    data = f.read()

records = []
offset = 0
while offset < len(data) - 8:
    record, offset = parse_usn_record(data, offset)
    if record:
        records.append(record)
    else:
        offset += 8  # Skip zeros

# Filter for deletion events
deletions = [r for r in records if 'FILE_DELETE' in r['reasons']]
creations = [r for r in records if 'FILE_CREATE' in r['reasons']]
renames = [r for r in records if 'RENAME_NEW_NAME' in r['reasons']]

print(f"Total USN records: {len(records)}")
print(f"File creations: {len(creations)}")
print(f"File deletions: {len(deletions)}")
print(f"File renames: {len(renames)}")

print("\n=== RECENT DELETIONS ===")
for r in deletions[-20:]:
    print(f"  [{r['timestamp']}] DELETED: {r['filename']} (MFT#{r['mft_entry']})")

# Write full journal to CSV
with open('/cases/case-2024-001/analysis/usn_journal.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'filename', 'mft_entry', 'parent_entry', 'reasons', 'usn'])
    writer.writeheader()
    writer.writerows(records)
PYEOF
```

### Step 5: Detect and Analyze Alternate Data Streams

```bash
# List all Alternate Data Streams in the image
find /mnt/evidence -exec getfattr -d {} \; 2>/dev/null | grep -i "ads\|zone\|stream"

# Using Sleuth Kit to find ADS
fls -r -o 2048 /cases/case-2024-001/images/evidence.dd | grep ":" | \
   tee /cases/case-2024-001/analysis/ads_list.txt

# Extract specific ADS content
# Format: icat image inode:ads_name
icat -o 2048 /cases/case-2024-001/images/evidence.dd 14523:hidden_stream \
   > /cases/case-2024-001/analysis/extracted_ads.bin

# Check Zone.Identifier streams (download origin tracking)
fls -r -o 2048 /cases/case-2024-001/images/evidence.dd | grep "Zone.Identifier" | \
   while read line; do
       inode=$(echo "$line" | awk '{print $2}' | tr -d ':')
       echo "=== $line ==="
       icat -o 2048 /cases/case-2024-001/images/evidence.dd "${inode}:Zone.Identifier" 2>/dev/null
       echo ""
   done > /cases/case-2024-001/analysis/zone_identifiers.txt

# Zone.Identifier content reveals:
# [ZoneTransfer]
# ZoneId=3          (3 = Internet, indicating file was downloaded)
# ReferrerUrl=https://malicious-site.com/payload.exe
# HostUrl=https://cdn.malicious-site.com/payload.exe
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| File slack | Unused space between file end and cluster boundary containing residual data |
| RAM slack | Portion of slack from file end to sector boundary (historically filled with RAM) |
| MFT ($MFT) | Master File Table - NTFS metadata database with entries for every file |
| USN Journal ($UsnJrnl) | Change journal recording all file/directory modifications on NTFS |
| Alternate Data Streams | NTFS feature allowing multiple data streams per file (hidden storage) |
| $STANDARD_INFORMATION | MFT attribute with timestamps modifiable by user-mode applications |
| $FILE_NAME | MFT attribute with timestamps only modifiable by the kernel |
| Timestomping | Anti-forensic technique modifying file timestamps to avoid detection |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| MFTECmd | Eric Zimmerman MFT and USN Journal parser with CSV output |
| MFTExplorer | Interactive GUI tool for MFT analysis |
| analyzeMFT | Python MFT parser with CSV/JSON output |
| The Sleuth Kit | File system forensics toolkit (fls, icat, blkls, istat) |
| bulk_extractor | Feature extraction from raw data including slack space |
| NTFS Log Tracker | Tool for parsing $LogFile transaction records |
| streams.exe | Sysinternals tool for listing NTFS Alternate Data Streams |
| Plaso | Super-timeline tool parsing MFT and USN Journal |

## Common Scenarios

**Scenario 1: Anti-Forensics Detection via Timestomping**
Compare $STANDARD_INFORMATION timestamps with $FILE_NAME timestamps in MFT entries, flag files where $SI timestamps predate $FN timestamps (impossible in normal operation), identify timestomped files as evidence of deliberate manipulation, correlate with other timeline evidence.

**Scenario 2: Hidden Data in Alternate Data Streams**
Scan for ADS attached to files beyond the standard Zone.Identifier, extract ADS content for analysis, check for hidden executables or documents stored in ADS, correlate ADS creation with user activity timeline, document findings for evidence.

**Scenario 3: Deleted File Reconstruction from MFT**
Parse MFT for inactive (deleted) entries, extract filenames, sizes, and timestamps of deleted files, recover file content using icat if data clusters are not overwritten, build list of deleted evidence files, correlate with USN Journal delete events.

**Scenario 4: File Activity Reconstruction from USN Journal**
Parse the USN Change Journal for the investigation period, identify file creation, modification, rename, and deletion events, reconstruct the sequence of file operations, detect evidence of data staging (create, copy, compress, delete pattern), identify anti-forensic file wiping.

## Output Format

```
File System Artifact Analysis:
  Volume: NTFS (Partition 2, 465 GB)
  Cluster Size: 4096 bytes

  MFT Analysis:
    Total Entries: 456,789
    Active Files: 234,567
    Deleted Entries: 12,345 (8,901 with recoverable metadata)
    Timestomped Files: 23 (SI/FN mismatch detected)

  USN Journal:
    Records Parsed: 2,345,678
    Date Range: 2024-01-01 to 2024-01-20
    File Creations: 45,678
    File Deletions: 23,456
    File Renames: 12,345

  Alternate Data Streams:
    Total ADS Found: 1,234
    Zone.Identifier: 890 (downloaded files)
    Custom/Suspicious ADS: 5 (hidden data detected)

  Slack Space:
    Total Slack: 12.3 GB
    Keyword Hits: 45 (passwords, credit cards)
    Carved Files: 23 from slack space

  Suspicious Findings:
    - 23 files with timestomped timestamps
    - 5 files with hidden ADS containing data
    - USN shows mass deletion on 2024-01-18 (anti-forensics)
    - Slack space contains residual email fragments

  Reports: /cases/case-2024-001/analysis/
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
