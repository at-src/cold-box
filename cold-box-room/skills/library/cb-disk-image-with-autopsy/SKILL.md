---
name: cb-disk-image-with-autopsy
skill_id: cb-disk-image-with-autopsy
journal_id: CB-SKL-035
description: Cold-box analyst playbook — Disk Image With Autopsy. Perform comprehensive
  forensic analysis of disk images using Autopsy to recover files, examine artifacts,
  and build investigation timelines.
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
- autopsy
- disk-analysis
- sleuth-kit
- file-recovery
- artifact-analysis
cold_box_version: 2
inspired_by: analyzing-disk-image-with-autopsy
---

# Disk Image With Autopsy (cold-box)

> **Journal ID:** `CB-SKL-035` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **`get_skill`** auto-records playbook adoption — do not `log_skill(adopted)`.
- **`run_sift_tool` / `analyze_scratch`** auto-record `audit_id` in audit log + journal — never cite IDs in report text.
- Optional **`log_skill(action=finding|corrected)`** for analyst conclusions only (no audit IDs).
- Prefer tools with `do_not_use` unset; `not_verified` only means not lab auto-tested — check `runnable` and `describe_sift_tool`.
- Load this playbook with `get_skill("cb-disk-image-with-autopsy")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-disk-image-with-autopsy")` → harness logs **`CB-SKL-035`**
2. `list_sift_tools(verified_only=true)` → pick tools from the map below
3. `describe_sift_tool(tool_id)` → `run_sift_tool(..., journal_id="CB-SKL-035")` → read scratch preview
4. `analyze_scratch` on scratch when needed; optional `log_skill(..., action="finding")` for conclusions
5. `submit_report` — plain language only; harness appends grounded audit table


## When to use

- When you have a forensic disk image and need structured analysis of its contents
- During investigations requiring file recovery, keyword searching, and timeline analysis
- When non-technical stakeholders need visual reports from forensic evidence
- For examining file system metadata, deleted files, and embedded artifacts
- When building a comprehensive case from multiple disk images

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `tsk_recover` | `SIFT-164` | yes | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `mactime` | `SIFT-168` | yes | yes |
| `autopsy` | `SIFT-047` | no | yes |
| `sigfind` | `SIFT-162` | yes | yes |
| `istat` | `SIFT-155` | no | yes |
| `unzip` | `SIFT-004` | yes | yes |
| `grep` | `SIFT-010` | yes | yes |
| `icat` | `SIFT-151` | yes | yes |
| `mmls` | `SIFT-160` | no | yes |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `fls` | `SIFT-148` | yes | yes |
| `dd` | `SIFT-034` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `tsk_recover` → `SIFT-164`

```json
{
  "tool_id": "SIFT-164",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] tsk_recover per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] img_stat per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `mactime` → `SIFT-168`

```json
{
  "tool_id": "SIFT-168",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] mactime per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `autopsy` → `SIFT-047`

```json
{
  "tool_id": "SIFT-047",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] autopsy per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `sigfind` → `SIFT-162`

```json
{
  "tool_id": "SIFT-162",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] sigfind per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `istat` → `SIFT-155`

```json
{
  "tool_id": "SIFT-155",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] istat per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `unzip` → `SIFT-004`

```json
{
  "tool_id": "SIFT-004",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] unzip per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-035] grep per playbook step",
  "why": "Executing cb-disk-image-with-autopsy \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

Harness-owned (you do not write audit IDs):

- **`get_skill`** → journal `adopted` for **`CB-SKL-035`**
- **`run_sift_tool` / `analyze_scratch`** → audit log + journal step with real **`audit_id`**
- **`log_skill(action=finding|corrected)`** → optional analyst note only (no audit IDs)
- **`submit_report`** → harness appends grounded evidence table for this session

## Cold-box path translation

When the procedure below uses host paths, translate as follows:

| Procedure path | Cold-box equivalent |
|----------------|---------------------|
| `C:\Evidence\...` / `/cases/...` | `{input_relpath}` on the sealed table (via viewport) |
| `C:\Output\...` / `/analysis/...` | `records/{case_id}/scratch/` (tool stdout/files) |
| Live SIEM / cloud console steps | **Reference only** on cold-box — note capability gap in journal |

Do not copy evidence off the table except into `records/{case_id}/scratch/` via `run_sift_tool`.


## Procedure

## Cold-box sealed E01 workflow (disk image)

When evidence is a sealed E01/DD on the operation table:

1. **Image facts** — `ewfinfo` / `img_stat` / `fsstat` or `mmls`; record NTFS `-o OFFSET`.
2. **List** — `fls` (SIFT-148) by directory inode (never unscoped `-r` on large E01).
3. **Extract file** — `icat` (SIFT-151, `output_style: inode_stream`) with inode from fls listing.
4. **Bulk recover** — tools with `output_style: scratch_dir_trailing` (e.g. tsk_recover): pass image flags only; harness supplies trailing scratch output directory per catalog.
5. **Inspect** — `analyze_scratch` on scratch paths (grep, strings, sqlite3, file, …).
6. **Journal** — `CB-SKL-035` + audit IDs.

Use `describe_sift_tool` for each tool's catalog metadata before running.

## When to Use
- When you have a forensic disk image and need structured analysis of its contents
- During investigations requiring file recovery, keyword searching, and timeline analysis
- When non-technical stakeholders need visual reports from forensic evidence
- For examining file system metadata, deleted files, and embedded artifacts
- When building a comprehensive case from multiple disk images

## Prerequisites
- Autopsy 4.x installed (Windows) or Autopsy 4.x with The Sleuth Kit (Linux)
- Forensic disk image in raw (dd), E01 (EnCase), or AFF format
- Minimum 8GB RAM (16GB recommended for large images)
- Java Runtime Environment (JRE) 8+ for Autopsy
- Sufficient disk space for the Autopsy case database (2-3x image size)
- Hash databases (NSRL, known-bad hashes) for file identification

## Workflow

### Step 1: Install Autopsy and Configure Environment

```bash
# On Linux, install Sleuth Kit and Autopsy
sudo apt-get install autopsy sleuthkit

# Download Autopsy 4.x (GUI version) from official source
wget https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
unzip autopsy-4.21.0.zip -d /opt/autopsy

# On Windows, run the MSI installer from sleuthkit.org
# Launch Autopsy
/opt/autopsy/bin/autopsy --nosplash

# For Sleuth Kit command-line analysis alongside Autopsy
sudo apt-get install sleuthkit
```

### Step 2: Create a New Case and Add the Disk Image

```
1. Launch Autopsy > "New Case"
2. Enter Case Name: "CASE-2024-001-Workstation"
3. Set Base Directory: /cases/case-2024-001/autopsy/
4. Enter Case Number, Examiner Name
5. Click "Add Data Source"
6. Select "Disk Image or VM File"
7. Browse to: /cases/case-2024-001/images/evidence.dd
8. Select Time Zone of the original system
9. Configure Ingest Modules (see Step 3)
```

```bash
# Alternatively, use Sleuth Kit CLI to verify the image first
img_stat /cases/case-2024-001/images/evidence.dd

# List partitions in the image
mmls /cases/case-2024-001/images/evidence.dd

# Output example:
# DOS Partition Table
# Offset Sector: 0
# Units are in 512-byte sectors
#      Slot    Start        End          Length       Description
#      00:  -----   0000000000   0000002047   0000002048   Primary Table (#0)
#      01:  00:00   0000002048   0001026047   0001024000   NTFS (0x07)
#      02:  00:01   0001026048   0976771071   0975745024   NTFS (0x07)

# List files in a partition (offset 2048 sectors)
fls -o 2048 /cases/case-2024-001/images/evidence.dd
```

### Step 3: Configure and Run Ingest Modules

```
Enable the following Autopsy Ingest Modules:
- Recent Activity: Extracts browser history, downloads, cookies, bookmarks
- Hash Lookup: Compares files against NSRL and known-bad hash sets
- File Type Identification: Identifies files by signature, not extension
- Keyword Search: Indexes content for full-text searching
- Email Parser: Extracts emails from PST, MBOX, EML files
- Extension Mismatch Detector: Finds files with wrong extensions
- Exif Parser: Extracts metadata from images (GPS, camera, timestamps)
- Encryption Detection: Identifies encrypted files and containers
- Interesting Files Identifier: Flags files matching custom rule sets
- Embedded File Extractor: Extracts files from ZIP, Office docs, PDFs
- Picture Analyzer: Categorizes images using PhotoDNA or hash matching
- Data Source Integrity: Verifies image hash during ingest
```

```bash
# Configure NSRL hash set for known-good filtering
# Download NSRL from https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl
wget https://s3.amazonaws.com/rds.nsrl.nist.gov/RDS/current/rds_modernm.zip
unzip rds_modernm.zip -d /opt/autopsy/hashsets/

# Import into Autopsy:
# Tools > Options > Hash Sets > Import > Select NSRLFile.txt
# Mark as "Known" (to filter out known-good files)
```

### Step 4: Analyze File System and Recover Deleted Files

```bash
# In Autopsy GUI: Navigate tree structure
# - Data Sources > evidence.dd > vol2 (NTFS)
# - Examine directory tree, note deleted files (marked with X)

# Using Sleuth Kit CLI for targeted recovery
# List deleted files
fls -rd -o 2048 /cases/case-2024-001/images/evidence.dd

# Recover a specific deleted file by inode
icat -o 2048 /cases/case-2024-001/images/evidence.dd 14523 > /cases/case-2024-001/recovered/deleted_document.docx

# Extract all files from a directory
tsk_recover -o 2048 -d /Users/suspect/Documents \
   /cases/case-2024-001/images/evidence.dd \
   /cases/case-2024-001/recovered/documents/

# Get detailed file metadata
istat -o 2048 /cases/case-2024-001/images/evidence.dd 14523
# Shows: creation, modification, access, MFT change timestamps, size, data runs
```

### Step 5: Perform Keyword Searches and Tag Evidence

```
In Autopsy:
1. Keyword Search panel > "Ad Hoc Keyword Search"
2. Search terms: credit card patterns, SSN regex, email addresses
3. Example regex for credit cards: \b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b
4. Example regex for SSN: \b\d{3}-\d{2}-\d{4}\b
5. Review results > Right-click items > "Add Tag"
6. Create tags: "Evidence-Critical", "Evidence-Supporting", "Requires-Review"
7. Add comments to tagged items documenting relevance
```

```bash
# Using Sleuth Kit for CLI keyword search
srch_strings -a -o 2048 /cases/case-2024-001/images/evidence.dd | \
   grep -iE '(password|secret|confidential)' > /cases/case-2024-001/keyword_hits.txt

# Search for specific file signatures
sigfind -o 2048 /cases/case-2024-001/images/evidence.dd 25504446
# 25504446 = %PDF header signature
```

### Step 6: Build Timeline and Generate Reports

```
In Autopsy:
1. Timeline viewer: Tools > Timeline
2. Select date range of interest (incident window)
3. Filter by event type: File Created, Modified, Accessed, Web Activity
4. Zoom into suspicious time periods
5. Export timeline events as CSV for external analysis

Generate Report:
1. Generate Report > HTML Report
2. Select tagged items and data sources to include
3. Configure report sections: file listings, keyword hits, timeline
4. Export to /cases/case-2024-001/reports/
```

```bash
# Using Sleuth Kit mactime for CLI timeline
fls -r -m "/" -o 2048 /cases/case-2024-001/images/evidence.dd > /cases/case-2024-001/bodyfile.txt

# Generate timeline from bodyfile
mactime -b /cases/case-2024-001/bodyfile.txt -d > /cases/case-2024-001/timeline.csv

# Filter timeline to specific date range
mactime -b /cases/case-2024-001/bodyfile.txt \
   -d 2024-01-15..2024-01-20 > /cases/case-2024-001/incident_timeline.csv
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Ingest Modules | Automated analysis plugins that process data sources upon import |
| MFT (Master File Table) | NTFS metadata structure recording all file entries and attributes |
| File carving | Recovering files from unallocated space using file signatures |
| Hash filtering | Using NSRL or custom hash sets to exclude known-good or flag known-bad files |
| Timeline analysis | Chronological reconstruction of file system and user activity events |
| Deleted file recovery | Restoring files whose directory entries are removed but data remains |
| Keyword indexing | Full-text search index built from all file content including slack space |
| Artifact extraction | Automated parsing of browser, email, registry, and OS-specific artifacts |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Autopsy | Open-source GUI forensic platform for disk image analysis |
| The Sleuth Kit (TSK) | Command-line forensic toolkit underlying Autopsy |
| fls | List files and directories in a disk image including deleted entries |
| icat | Extract file content by inode number from a disk image |
| mactime | Generate timeline from TSK bodyfile format |
| mmls | Display partition layout of a disk image |
| NSRL | NIST hash database for identifying known software files |
| sigfind | Search for file signatures at the sector level |

## Common Scenarios

**Scenario 1: Employee Data Theft Investigation**
Import the employee workstation image, run all ingest modules, search for company-confidential file names and keywords, examine USB connection artifacts in Recent Activity, check for cloud storage client artifacts, review deleted files for evidence of data staging, generate HTML report for legal team.

**Scenario 2: Malware Infection Forensics**
Add the compromised system image, enable Extension Mismatch and Encryption Detection modules, examine the prefetch directory for execution evidence, search for known malware hashes, build timeline around the infection window, extract suspicious executables for further analysis in a sandbox.

**Scenario 3: Child Exploitation Material (CSAM) Investigation**
Import image with PhotoDNA and Project VIC hash sets enabled, run Picture Analyzer module, hash all image files against known-bad databases, tag and categorize matches by severity, generate law enforcement report with chain of custody documentation.

**Scenario 4: Intellectual Property Dispute**
Import multiple employee disk images as separate data sources in one case, perform keyword searches for proprietary terms and project names, compare file hashes between sources, build timeline showing file access and transfer patterns, export evidence for legal review.

## Output Format

```
Autopsy Case Analysis Summary:
  Case:           CASE-2024-001-Workstation
  Image:          evidence.dd (500GB NTFS)
  Partitions:     2 (System Reserved + Primary)
  Total Files:    245,832
  Deleted Files:  12,456 (recoverable: 8,234)

  Ingest Results:
    Hash Matches (Known Bad):  3 files
    Extension Mismatches:      17 files
    Keyword Hits:              234 across 45 files
    Encrypted Files:           5 containers detected
    EXIF Data Extracted:       1,245 images with metadata

  Tagged Evidence:
    Critical:     12 items
    Supporting:   34 items
    Review:       67 items

  Timeline Events:  1,234,567 entries (filtered to incident window: 892)
  Report:          /cases/case-2024-001/reports/autopsy_report.html
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
