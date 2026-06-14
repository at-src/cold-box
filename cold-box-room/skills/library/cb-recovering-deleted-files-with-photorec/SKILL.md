---
name: cb-recovering-deleted-files-with-photorec
skill_id: cb-recovering-deleted-files-with-photorec
journal_id: CB-SKL-105
description: Cold-box analyst playbook — Recovering Deleted Files With Photorec. Recover
  deleted files from disk images and storage media using PhotoRec's file signature-based
  carving engine regardless of file system damage.
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
- file-recovery
- photorec
- file-carving
- data-recovery
- evidence-recovery
cold_box_version: 2
inspired_by: recovering-deleted-files-with-photorec
---

# Recovering Deleted Files With Photorec (cold-box)

> **Journal ID:** `CB-SKL-105` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-105`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-recovering-deleted-files-with-photorec")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-recovering-deleted-files-with-photorec")` → note **`CB-SKL-105`**
2. `log_skill(case_id, journal_id="CB-SKL-105", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-105` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When recovering deleted files from a forensic disk image or storage device
- When the file system is corrupted, formatted, or overwritten
- During investigations requiring recovery of documents, images, videos, or databases
- When file system metadata is unavailable but raw data sectors remain intact
- For recovering files from memory cards, USB drives, and hard drives

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `sha256sum` | `SIFT-018` | yes | yes |
| `hashdeep` | `SIFT-066` | yes | yes |
| `photorec` | `SIFT-041` | no | yes |
| `testdisk` | `SIFT-108` | no | yes |
| `foremost` | `SIFT-040` | yes | yes |
| `exiftool` | `SIFT-055` | yes | yes |
| `scalpel` | `SIFT-042` | yes | yes |
| `dcfldd` | `SIFT-033` | no | yes |
| `sort` | `SIFT-020` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
| `uniq` | `SIFT-025` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `sed` | `SIFT-016` | yes | yes |
| `cut` | `SIFT-006` | yes | yes |
| `dd` | `SIFT-034` | no | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] mmls per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] img_stat per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] sha256sum per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `hashdeep` → `SIFT-066`

```json
{
  "tool_id": "SIFT-066",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] hashdeep per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `photorec` → `SIFT-041`

```json
{
  "tool_id": "SIFT-041",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] photorec per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `testdisk` → `SIFT-108`

```json
{
  "tool_id": "SIFT-108",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] testdisk per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `foremost` → `SIFT-040`

```json
{
  "tool_id": "SIFT-040",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] foremost per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

### `exiftool` → `SIFT-055`

```json
{
  "tool_id": "SIFT-055",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-105] exiftool per playbook step",
  "why": "Executing cb-recovering-deleted-files-with-photorec \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-105` (`cb-recovering-deleted-files-with-photorec`)

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
- When recovering deleted files from a forensic disk image or storage device
- When the file system is corrupted, formatted, or overwritten
- During investigations requiring recovery of documents, images, videos, or databases
- When file system metadata is unavailable but raw data sectors remain intact
- For recovering files from memory cards, USB drives, and hard drives

## Prerequisites
- PhotoRec installed (part of TestDisk suite)
- Forensic disk image or direct device access (read-only)
- Sufficient output storage space (potentially larger than source)
- Write-blocker if working with original media
- Root/sudo privileges for device access
- Knowledge of target file types for focused recovery

## Workflow

### Step 1: Install PhotoRec and Prepare the Environment

```bash
# Install TestDisk (includes PhotoRec) on Debian/Ubuntu
sudo apt-get install testdisk

# On RHEL/CentOS
sudo yum install testdisk

# On macOS
brew install testdisk

# Verify installation
photorec --version

# Create output directory structure
mkdir -p /cases/case-2024-001/recovered/{all,documents,images,databases}

# Verify the forensic image
file /cases/case-2024-001/images/evidence.dd
ls -lh /cases/case-2024-001/images/evidence.dd
```

### Step 2: Run PhotoRec in Interactive Mode

```bash
# Launch PhotoRec against a forensic image
photorec /cases/case-2024-001/images/evidence.dd

# Interactive menu steps:
# 1. Select the disk image: evidence.dd
# 2. Select partition table type: [Intel] for MBR, [EFI GPT] for GPT
# 3. Select partition to scan (or "No partition" for whole disk)
# 4. Select filesystem type: [ext2/ext3/ext4] or [Other] for NTFS/FAT
# 5. Choose scan scope: [Free] (unallocated only) or [Whole] (entire partition)
# 6. Select output directory: /cases/case-2024-001/recovered/all/
# 7. Press C to confirm and begin recovery

# For direct device scanning (with write-blocker)
sudo photorec /dev/sdb
```

### Step 3: Run PhotoRec with Command-Line Options for Targeted Recovery

```bash
# Non-interactive mode with specific file types
photorec /d /cases/case-2024-001/recovered/documents/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   partition_table,options,mode,fileopt,search

# Recover only specific file types using photorec command mode
photorec /d /cases/case-2024-001/recovered/documents/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   options,keep_corrupted_file,enable \
   fileopt,everything,disable \
   fileopt,doc,enable \
   fileopt,docx,enable \
   fileopt,pdf,enable \
   fileopt,xlsx,enable \
   search

# Recover only image files
photorec /d /cases/case-2024-001/recovered/images/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   fileopt,everything,disable \
   fileopt,jpg,enable \
   fileopt,png,enable \
   fileopt,gif,enable \
   fileopt,bmp,enable \
   fileopt,tif,enable \
   search

# Recover database files
photorec /d /cases/case-2024-001/recovered/databases/ \
   /cmd /cases/case-2024-001/images/evidence.dd \
   fileopt,everything,disable \
   fileopt,sqlite,enable \
   fileopt,dbf,enable \
   search
```

### Step 4: Organize and Catalog Recovered Files

```bash
# PhotoRec outputs files into recup_dir.1, recup_dir.2, etc.
ls /cases/case-2024-001/recovered/all/

# Count recovered files by type
find /cases/case-2024-001/recovered/all/ -type f | \
   sed 's/.*\.//' | sort | uniq -c | sort -rn > /cases/case-2024-001/recovered/file_type_summary.txt

# Sort recovered files into directories by extension
cd /cases/case-2024-001/recovered/all/
for ext in jpg png pdf docx xlsx pptx zip sqlite; do
   mkdir -p /cases/case-2024-001/recovered/sorted/$ext
   find . -name "*.$ext" -exec cp {} /cases/case-2024-001/recovered/sorted/$ext/ \;
done

# Generate SHA-256 hashes for all recovered files
find /cases/case-2024-001/recovered/all/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/recovered/recovered_hashes.txt

# Generate file listing with metadata
find /cases/case-2024-001/recovered/all/ -type f \
   -printf "%f\t%s\t%T+\t%p\n" | sort > /cases/case-2024-001/recovered/file_listing.txt
```

### Step 5: Validate and Filter Recovered Files

```bash
# Verify file integrity using file signatures
find /cases/case-2024-001/recovered/all/ -type f -exec file {} \; \
   > /cases/case-2024-001/recovered/file_signatures.txt

# Find files with mismatched extension/signature
while IFS= read -r line; do
   filepath=$(echo "$line" | cut -d: -f1)
   filetype=$(echo "$line" | cut -d: -f2-)
   ext="${filepath##*.}"
   if [[ "$ext" == "jpg" ]] && ! echo "$filetype" | grep -qi "JPEG"; then
      echo "MISMATCH: $filepath -> $filetype"
   fi
done < /cases/case-2024-001/recovered/file_signatures.txt > /cases/case-2024-001/recovered/mismatches.txt

# Filter out known-good files using NSRL hash comparison
hashdeep -r -c sha256 /cases/case-2024-001/recovered/all/ | \
   grep -vFf /opt/nsrl/nsrl_sha256.txt > /cases/case-2024-001/recovered/unknown_files.txt

# Remove zero-byte and corrupted files
find /cases/case-2024-001/recovered/all/ -type f -empty -delete
find /cases/case-2024-001/recovered/all/ -name "*.jpg" -exec jpeginfo -c {} \; 2>&1 | \
   grep "ERROR" > /cases/case-2024-001/recovered/corrupted_images.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| File carving | Recovering files from raw data using file header/footer signatures |
| File signatures | Magic bytes at the start of files identifying their type (e.g., FF D8 FF for JPEG) |
| Unallocated space | Disk sectors not assigned to any active file; may contain deleted data |
| Fragmented files | Files stored in non-contiguous sectors; harder to carve completely |
| Cluster/Block size | Minimum allocation unit on a file system; affects carving granularity |
| File footer | Byte sequence marking the end of a file (not all formats have footers) |
| Data remanence | Residual data remaining after deletion until sectors are overwritten |
| False positives | Carved artifacts that match signatures but contain corrupted or partial data |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| PhotoRec | Open-source file carving tool supporting 300+ file formats |
| TestDisk | Companion tool for partition recovery and repair |
| Foremost | Alternative file carver originally developed by US Air Force OSI |
| Scalpel | High-performance file carver based on Foremost |
| hashdeep | Recursive hash computation and audit tool |
| jpeginfo | JPEG file integrity verification |
| file | Unix utility identifying file types by magic bytes |
| exiftool | Extract metadata from recovered image and document files |

## Common Scenarios

**Scenario 1: Recovering Deleted Evidence from a Suspect's USB Drive**
Image the USB drive with dcfldd, run PhotoRec targeting document and image formats, organize by file type, hash all recovered files, compare against known-bad hash sets, extract metadata from images for GPS and timestamp information.

**Scenario 2: Formatted Hard Drive Recovery**
Run PhotoRec in "Whole" mode against the entire formatted partition, recover all file types, expect higher false positive rate due to file fragmentation, validate recovered files with signature checking, catalog and hash for evidence chain.

**Scenario 3: Memory Card from a Surveillance Camera**
Recover deleted video files (AVI, MP4, MOV) from the memory card image, use targeted file type selection to speed recovery, verify video files are playable, extract frame timestamps, document recovery in case notes.

**Scenario 4: Corrupted File System on Evidence Drive**
When file system metadata is destroyed, PhotoRec bypasses the file system entirely and carves from raw sectors, recover maximum possible data, accept that file names and directory structure will be lost, rename files based on content during review.

## Output Format

```
PhotoRec Recovery Summary:
  Source Image:     evidence.dd (500 GB)
  Partition:        NTFS (Partition 2)
  Scan Mode:        Free space only

  Files Recovered:  4,523
    Documents:      234 (doc: 45, docx: 89, pdf: 67, xlsx: 33)
    Images:         2,145 (jpg: 1,890, png: 198, gif: 57)
    Videos:         34 (mp4: 22, avi: 12)
    Archives:       67 (zip: 45, rar: 22)
    Databases:      12 (sqlite: 8, dbf: 4)
    Other:          2,031

  Data Recovered:   12.4 GB
  Corrupted Files:  312 (flagged for review)
  Output Directory: /cases/case-2024-001/recovered/all/
  Hash Manifest:    /cases/case-2024-001/recovered/recovered_hashes.txt
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
