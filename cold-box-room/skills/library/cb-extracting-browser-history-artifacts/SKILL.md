---
name: cb-extracting-browser-history-artifacts
skill_id: cb-extracting-browser-history-artifacts
journal_id: CB-SKL-041
description: Cold-box analyst playbook — Extracting Browser History Artifacts. Extract
  and analyze browser history, cookies, cache, downloads, and bookmarks from Chrome,
  Firefox, and Edge for forensic evidence of user web activity.
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
- browser-forensics
- chrome
- firefox
- edge
- web-history
- artifact-extraction
cold_box_version: 2
inspired_by: extracting-browser-history-artifacts
---

# Extracting Browser History Artifacts (cold-box)

> **Journal ID:** `CB-SKL-041` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **`get_skill`** auto-records playbook adoption — do not `log_skill(adopted)`.
- **`run_sift_tool` / `analyze_scratch`** auto-record `audit_id` in audit log + journal — never cite IDs in report text.
- Optional **`log_skill(action=finding|corrected)`** for analyst conclusions only (no audit IDs).
- Prefer tools with `do_not_use` unset; `not_verified` only means not lab auto-tested — check `runnable` and `describe_sift_tool`.
- Load this playbook with `get_skill("cb-extracting-browser-history-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-extracting-browser-history-artifacts")` → harness logs **`CB-SKL-041`**
2. `list_sift_tools(verified_only=true)` → pick tools from the map below
3. `describe_sift_tool(tool_id)` → `run_sift_tool(..., journal_id="CB-SKL-041")` → read scratch preview
4. `analyze_scratch` on scratch when needed; optional `log_skill(..., action="finding")` for conclusions
5. `submit_report` — plain language only; harness appends grounded audit table


## When to use

- When investigating user web activity as part of a forensic examination
- During insider threat investigations to establish patterns of data exfiltration
- When tracing user visits to malicious or policy-violating websites
- For correlating browser activity with other forensic artifacts and timelines
- When investigating phishing attacks to identify which links were clicked

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `sha256sum` | `SIFT-018` | yes | yes |
| `sqlite3` | `SIFT-021` | yes | yes |
| `autopsy` | `SIFT-047` | no | yes |
| `mount` | `SIFT-075` | no | yes |
| `find` | `SIFT-009` | yes | yes |
| `fls` | `SIFT-148` | yes | yes |
| `icat` | `SIFT-151` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `dd` | `SIFT-034` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] mmls per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] img_stat per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] sha256sum per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `sqlite3` → `SIFT-021`

```json
{
  "tool_id": "SIFT-021",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] sqlite3 per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `autopsy` → `SIFT-047`

```json
{
  "tool_id": "SIFT-047",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] autopsy per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] mount per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] find per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-041] file per playbook step",
  "why": "Executing cb-extracting-browser-history-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

Harness-owned (you do not write audit IDs):

- **`get_skill`** → journal `adopted` for **`CB-SKL-041`**
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

## Cold-box sealed E01 workflow (Firefox on disk image)

When evidence is a sealed E01/DD on the operation table (not a mounted path):

1. **Partition offset** — `fsstat` / `mmls` / skill notes; record offset (often `-o 63` on XP-era images).
2. **Locate profile** — `fls` (SIFT-148): `extra_args: ["-o", OFFSET, PROFILE_INODE]` then profile directory inode (e.g. `…/Mozilla/Firefox/Profiles/…/`).
3. **Extract databases** — `icat` (SIFT-151, catalog `output_style: inode_stream`): `extra_args: ["-o", OFFSET, "INODE-FOR-FILE"]` for `places.sqlite`, `formhistory.sqlite`, `cookies.sqlite`, `downloads.sqlite`.
4. **Query** — `analyze_scratch` with `sqlite3` on the scratch extract (see Step 2–3 below for SQL). Use `strings`/`grep` when sqlite is unsuitable.
5. **Journal** — log findings with `CB-SKL-041`, cite each `audit_id`.

Use `describe_sift_tool` to read `output_style`, `runnable`, and `common_flags` before each new binary.

## When to Use
- When investigating user web activity as part of a forensic examination
- During insider threat investigations to establish patterns of data exfiltration
- When tracing user visits to malicious or policy-violating websites
- For correlating browser activity with other forensic artifacts and timelines
- When investigating phishing attacks to identify which links were clicked

## Prerequisites
- Forensic image or access to user profile directories
- SQLite3 for querying browser databases
- Hindsight, BrowsingHistoryView, or DB Browser for SQLite
- Knowledge of browser artifact file locations per OS
- Python 3 with sqlite3 module for automated extraction
- Understanding of Chrome, Firefox, and Edge storage formats

## Workflow

### Step 1: Locate Browser Artifact Files

```bash
# Mount forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Chrome artifact locations (Windows)
CHROME_WIN="/mnt/evidence/Users/suspect/AppData/Local/Google/Chrome/User Data/Default"
# Key files: History, Cookies, Login Data, Web Data, Bookmarks, Preferences,
#            Cache/, GPUCache/, Local Storage/, Session Storage/, IndexedDB/

# Firefox artifact locations (Windows)
FIREFOX_WIN="/mnt/evidence/Users/suspect/AppData/Roaming/Mozilla/Firefox/Profiles/*.default-release"
# Key files: places.sqlite, cookies.sqlite, formhistory.sqlite, logins.json,
#            key4.db, sessionstore.jsonlz4, webappsstore.sqlite

# Edge (Chromium) artifact locations (Windows)
EDGE_WIN="/mnt/evidence/Users/suspect/AppData/Local/Microsoft/Edge/User Data/Default"

# Copy artifacts to working directory
mkdir -p /cases/case-2024-001/browser/{chrome,firefox,edge}
cp -r "$CHROME_WIN"/{History,Cookies,Downloads,"Login Data","Web Data",Bookmarks} \
   /cases/case-2024-001/browser/chrome/ 2>/dev/null
cp -r $FIREFOX_WIN/{places.sqlite,cookies.sqlite,formhistory.sqlite,logins.json} \
   /cases/case-2024-001/browser/firefox/ 2>/dev/null
cp -r "$EDGE_WIN"/{History,Cookies,Downloads} \
   /cases/case-2024-001/browser/edge/ 2>/dev/null

# Hash artifacts for integrity
find /cases/case-2024-001/browser/ -type f -exec sha256sum {} \; \
   > /cases/case-2024-001/browser/artifact_hashes.txt
```

### Step 2: Extract Chrome Browsing History and Downloads

```bash
# Query Chrome History database
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_history.csv

SELECT
    urls.url,
    urls.title,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') AS last_visit,
    urls.visit_count,
    urls.typed_count,
    visits.transition & 0xFF AS transition_type
FROM urls
LEFT JOIN visits ON urls.id = visits.url
ORDER BY urls.last_visit_time DESC;
SQL

# Extract Chrome downloads
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_downloads.csv

SELECT
    current_path,
    tab_url AS source_url,
    total_bytes,
    datetime(start_time/1000000-11644473600, 'unixepoch') AS start_time,
    datetime(end_time/1000000-11644473600, 'unixepoch') AS end_time,
    state,
    danger_type,
    mime_type
FROM downloads
ORDER BY start_time DESC;
SQL

# Extract Chrome search terms
sqlite3 /cases/case-2024-001/browser/chrome/History << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_searches.csv

SELECT
    term,
    urls.url,
    datetime(urls.last_visit_time/1000000-11644473600, 'unixepoch') AS search_time
FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id
ORDER BY urls.last_visit_time DESC;
SQL
```

### Step 3: Extract Firefox Browsing History

```bash
# Query Firefox places.sqlite for history
sqlite3 /cases/case-2024-001/browser/firefox/places.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_history.csv

SELECT
    moz_places.url,
    moz_places.title,
    datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') AS visit_date,
    moz_places.visit_count,
    moz_historyvisits.visit_type
FROM moz_places
JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id
ORDER BY moz_historyvisits.visit_date DESC;
SQL

# Extract Firefox bookmarks
sqlite3 /cases/case-2024-001/browser/firefox/places.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_bookmarks.csv

SELECT
    moz_bookmarks.title,
    moz_places.url,
    datetime(moz_bookmarks.dateAdded/1000000, 'unixepoch') AS date_added,
    datetime(moz_bookmarks.lastModified/1000000, 'unixepoch') AS last_modified
FROM moz_bookmarks
JOIN moz_places ON moz_bookmarks.fk = moz_places.id
WHERE moz_bookmarks.type = 1
ORDER BY moz_bookmarks.dateAdded DESC;
SQL

# Extract Firefox form history (search terms, form fills)
sqlite3 /cases/case-2024-001/browser/firefox/formhistory.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_forms.csv

SELECT
    fieldname,
    value,
    timesUsed,
    datetime(firstUsed/1000000, 'unixepoch') AS first_used,
    datetime(lastUsed/1000000, 'unixepoch') AS last_used
FROM moz_formhistory
ORDER BY lastUsed DESC;
SQL
```

### Step 4: Extract Cookies and Stored Credentials

```bash
# Extract Chrome cookies
sqlite3 /cases/case-2024-001/browser/chrome/Cookies << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_cookies.csv

SELECT
    host_key,
    name,
    path,
    datetime(creation_utc/1000000-11644473600, 'unixepoch') AS created,
    datetime(expires_utc/1000000-11644473600, 'unixepoch') AS expires,
    datetime(last_access_utc/1000000-11644473600, 'unixepoch') AS last_access,
    is_secure,
    is_httponly,
    is_persistent
FROM cookies
ORDER BY last_access_utc DESC;
SQL

# Extract Firefox cookies
sqlite3 /cases/case-2024-001/browser/firefox/cookies.sqlite << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/firefox_cookies.csv

SELECT
    host,
    name,
    path,
    datetime(creationTime/1000000, 'unixepoch') AS created,
    datetime(expiry, 'unixepoch') AS expires,
    datetime(lastAccessed/1000000, 'unixepoch') AS last_access,
    isSecure,
    isHttpOnly
FROM moz_cookies
ORDER BY lastAccessed DESC;
SQL

# Note: Chrome Login Data is encrypted with DPAPI (Windows) or keychain (Mac)
# Extract stored login URLs (passwords are encrypted)
sqlite3 /cases/case-2024-001/browser/chrome/"Login Data" << 'SQL'
.headers on
.mode csv
.output /cases/case-2024-001/analysis/chrome_logins.csv

SELECT
    origin_url,
    action_url,
    username_value,
    datetime(date_created/1000000-11644473600, 'unixepoch') AS date_created,
    datetime(date_last_used/1000000-11644473600, 'unixepoch') AS date_last_used,
    times_used
FROM logins
ORDER BY date_last_used DESC;
SQL
```

### Step 5: Use Hindsight for Comprehensive Chrome Analysis

```bash
# Install Hindsight
pip install pyhindsight

# Run Hindsight against Chrome profile
hindsight -i "/cases/case-2024-001/browser/chrome/" \
   -o /cases/case-2024-001/analysis/hindsight_report \
   -f xlsx

# Hindsight automatically extracts:
# - Browsing history with timestamps
# - Downloads with source URLs
# - Cookies with decryption (where possible)
# - Cache records
# - Local Storage entries
# - Autofill data
# - Saved passwords (encrypted)
# - Preferences and extensions
# - Session/tab recovery data

# For JSONL output (easier to parse)
hindsight -i "/cases/case-2024-001/browser/chrome/" \
   -o /cases/case-2024-001/analysis/hindsight_report \
   -f jsonl
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Chrome timestamp | Microseconds since January 1, 1601 (WebKit/Chrome epoch) |
| Firefox timestamp | Microseconds since January 1, 1970 (Unix epoch in microseconds) |
| Transition types | How a URL was accessed: typed (1), link (0), bookmark (1), redirect (5/6) |
| DPAPI encryption | Windows Data Protection API encrypting stored passwords and cookies |
| places.sqlite | Firefox combined history and bookmark database |
| SQLite WAL | Write-Ahead Log that may contain recently deleted browser records |
| Session restore | Browser data preserving open tabs across restarts |
| IndexedDB | Browser-based database that may contain web application data |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Hindsight | Comprehensive Chrome/Chromium forensic analysis tool |
| sqlite3 | Command-line SQLite database query tool |
| DB Browser for SQLite | GUI tool for browsing SQLite databases |
| BrowsingHistoryView | NirSoft tool for viewing browser history across all browsers |
| ChromeCacheView | NirSoft tool for examining Chrome cache contents |
| MZCacheView | NirSoft tool for Firefox cache analysis |
| KAPE | Automated artifact collection including browser data |
| Autopsy | Full forensic platform with browser artifact ingest modules |

## Common Scenarios

**Scenario 1: Phishing Investigation**
Extract browser history around the reported phishing timeframe, identify the phishing URL that was visited, check downloads for malicious attachments, examine cookies for session tokens that may have been stolen, correlate with email header analysis.

**Scenario 2: Data Exfiltration via Cloud Services**
Search history for cloud storage URLs (Dropbox, Google Drive, OneDrive, Mega), examine downloads and uploads, check form history for file names entered, review cookies for active cloud service sessions during the investigation period.

**Scenario 3: Policy Violation Investigation**
Extract complete browsing history for the investigation period, categorize sites visited, identify access to prohibited content categories, document timestamps and visit duration, correlate with network proxy logs for verification.

**Scenario 4: Malware Delivery Vector Analysis**
Trace the chain of redirects leading to a drive-by download, examine the downloads database for the malware payload, check cache for exploit kit landing pages, identify the initial referrer URL that started the infection chain.

## Output Format

```
Browser Forensics Summary:
  User Profile: suspect (Windows 10)
  Browsers Found: Chrome 120, Firefox 121, Edge 120

  Chrome Analysis:
    History Entries:    12,456
    Downloads:          234
    Saved Passwords:    67 sites (encrypted)
    Cookies:            3,456
    Bookmarks:          89

  Firefox Analysis:
    History Entries:    5,678
    Form Entries:       234
    Bookmarks:          45
    Cookies:            1,234

  Suspicious Findings:
    - Visited known phishing URL at 2024-01-15 14:32 UTC
    - Downloaded "invoice_update.exe" from suspicious domain
    - Cloud storage (mega.nz) accessed 15 times in 2-hour window
    - Search queries: "how to encrypt files", "secure file transfer"

  Reports:
    Chrome History:   /analysis/chrome_history.csv
    Firefox History:  /analysis/firefox_history.csv
    Full Report:      /analysis/hindsight_report.xlsx
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
