---
name: cb-cloud-storage-forensic-acquisition
skill_id: cb-cloud-storage-forensic-acquisition
journal_id: CB-SKL-015
description: Cold-box analyst playbook — Cloud Storage Forensic Acquisition. Perform
  forensic acquisition and analysis of cloud storage services including Google Drive,
  OneDrive, Dropbox, and Box by collecting both API-based remote data and local sync
  client artifacts from endpoint devices.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- cloud
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- cloud-forensics
- google-drive
- onedrive
- dropbox
- box
- cloud-acquisition
- api-forensics
- sync-client
- endpoint-artifacts
- magnet-axiom
cold_box_version: 2
inspired_by: performing-cloud-storage-forensic-acquisition
---

# Cloud Storage Forensic Acquisition (cold-box)

> **Journal ID:** `CB-SKL-015` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-015`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-cloud-storage-forensic-acquisition")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-cloud-storage-forensic-acquisition")` → note **`CB-SKL-015`**
2. `log_skill(case_id, journal_id="CB-SKL-015", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-015` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing cloud storage forensic acquisition
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sqlite3` | `SIFT-021` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-015] powershell per playbook step",
  "why": "Executing cb-cloud-storage-forensic-acquisition \u2014 see Procedure section",
  "extra_args": []
}
```

### `sqlite3` → `SIFT-021`

```json
{
  "tool_id": "SIFT-021",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-015] sqlite3 per playbook step",
  "why": "Executing cb-cloud-storage-forensic-acquisition \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-015] file per playbook step",
  "why": "Executing cb-cloud-storage-forensic-acquisition \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-015` (`cb-cloud-storage-forensic-acquisition`)

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

## Overview

Cloud storage forensic acquisition involves collecting digital evidence from services like Google Drive, OneDrive, Dropbox, and Box through both API-based remote acquisition and local endpoint artifact analysis. Modern investigations must address the challenge that cloud-synced files may exist in multiple states: locally synchronized, cloud-only (on-demand), cached, and deleted. Endpoint devices that have synchronized with cloud storage contain a wealth of metadata about locally synced files, files present only in the cloud, and even deleted items recoverable from cache folders. API-based acquisition using service-specific APIs provides direct access to remote data with valid credentials and proper legal authorization.


## When to Use

- When conducting security assessments that involve performing cloud storage forensic acquisition
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Legal authorization (warrant, consent, or corporate policy) for cloud data access
- Valid user credentials or administrative access tokens
- Magnet AXIOM Cloud, Cellebrite Cloud Analyzer, or equivalent tool
- KAPE with cloud storage target files
- Python 3.8+ with google-api-python-client, msal, dropbox SDK
- Network connectivity for API-based acquisition

## Acquisition Methods

### Method 1: API-Based Remote Acquisition

#### Google Drive API Acquisition

```python
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import os
import json
from datetime import datetime


class GoogleDriveForensicAcquisition:
    """Forensically acquire files and metadata from Google Drive via API."""

    def __init__(self, credentials_path: str, output_dir: str):
        self.creds = Credentials.from_authorized_user_file(credentials_path)
        self.service = build("drive", "v3", credentials=self.creds)
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.acquisition_log = []

    def list_all_files(self, include_trashed: bool = True) -> list:
        """List all files including trashed items."""
        files = []
        page_token = None
        query = "" if include_trashed else "trashed = false"

        while True:
            results = self.service.files().list(
                q=query,
                pageSize=1000,
                fields="nextPageToken, files(id, name, mimeType, size, "
                       "createdTime, modifiedTime, trashed, trashedTime, "
                       "owners, sharingUser, permissions, md5Checksum, "
                       "parents, webViewLink, driveId)",
                pageToken=page_token
            ).execute()

            files.extend(results.get("files", []))
            page_token = results.get("nextPageToken")
            if not page_token:
                break

        return files

    def download_file(self, file_id: str, file_name: str, mime_type: str) -> str:
        """Download a file from Google Drive preserving forensic integrity."""
        output_path = os.path.join(self.output_dir, file_name)

        if mime_type.startswith("application/vnd.google-apps"):
            export_formats = {
                "application/vnd.google-apps.document": "application/pdf",
                "application/vnd.google-apps.spreadsheet": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.google-apps.presentation": "application/pdf",
            }
            export_mime = export_formats.get(mime_type, "application/pdf")
            request = self.service.files().export_media(fileId=file_id, mimeType=export_mime)
        else:
            request = self.service.files().get_media(fileId=file_id)

        with io.FileIO(output_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()

        self.acquisition_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "file_id": file_id,
            "file_name": file_name,
            "output_path": output_path,
            "action": "downloaded"
        })
        return output_path

    def get_activity_log(self, file_id: str) -> list:
        """Retrieve activity/revision history for a specific file."""
        revisions = self.service.revisions().list(
            fileId=file_id,
            fields="revisions(id, modifiedTime, lastModifyingUser, size, md5Checksum)"
        ).execute()
        return revisions.get("revisions", [])

    def export_acquisition_report(self) -> str:
        """Export acquisition log for chain of custody documentation."""
        report_path = os.path.join(self.output_dir, "acquisition_log.json")
        with open(report_path, "w") as f:
            json.dump({
                "acquisition_start": self.acquisition_log[0]["timestamp"] if self.acquisition_log else None,
                "acquisition_end": datetime.utcnow().isoformat(),
                "total_files": len(self.acquisition_log),
                "entries": self.acquisition_log
            }, f, indent=2)
        return report_path
```

#### OneDrive / Microsoft 365 API Acquisition

```python
import msal
import requests
import os
import json
from datetime import datetime


class OneDriveForensicAcquisition:
    """Forensically acquire files and metadata from OneDrive via Microsoft Graph API."""

    def __init__(self, client_id: str, tenant_id: str, client_secret: str, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.app = msal.ConfidentialClientApplication(
            client_id, authority=authority, client_credential=client_secret
        )
        token_result = self.app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        self.access_token = token_result.get("access_token")
        self.headers = {"Authorization": f"Bearer {self.access_token}"}
        self.base_url = "https://graph.microsoft.com/v1.0"

    def list_user_files(self, user_id: str) -> list:
        """List all files in user's OneDrive."""
        url = f"{self.base_url}/users/{user_id}/drive/root/children"
        files = []
        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            files.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return files

    def download_file(self, user_id: str, item_id: str, filename: str) -> str:
        """Download a file from OneDrive."""
        url = f"{self.base_url}/users/{user_id}/drive/items/{item_id}/content"
        response = requests.get(url, headers=self.headers, stream=True)
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return output_path

    def get_deleted_items(self, user_id: str) -> list:
        """Retrieve items from OneDrive recycle bin."""
        url = f"{self.base_url}/users/{user_id}/drive/special/recyclebin/children"
        response = requests.get(url, headers=self.headers)
        return response.json().get("value", [])
```

### Method 2: Local Endpoint Artifact Collection

#### KAPE Targets for Cloud Storage

```powershell
# Collect all cloud storage artifacts using KAPE
kape.exe --tsource C: --tdest C:\Output\CloudArtifacts --target GoogleDrive,OneDrive,Dropbox,Box

# OneDrive artifacts
# %USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\
# %USERPROFILE%\AppData\Local\Microsoft\OneDrive\settings\
# %USERPROFILE%\OneDrive\

# Google Drive artifacts
# %USERPROFILE%\AppData\Local\Google\DriveFS\
# Contains metadata SQLite databases and cached files

# Dropbox artifacts
# %USERPROFILE%\AppData\Local\Dropbox\
# %USERPROFILE%\Dropbox\.dropbox.cache\
# Contains filecache.dbx (encrypted SQLite), host.dbx, config.dbx
```

#### OneDrive Local Database Analysis

```python
import sqlite3
import os

def analyze_onedrive_sync_engine(db_path: str) -> list:
    """Analyze OneDrive SyncEngineDatabase for file metadata."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Query for all tracked files including cloud-only items
    cursor.execute("""
        SELECT fileName, fileSize, lastChange,
               resourceID, parentResourceID, eTag
        FROM od_ClientFile_Records
        ORDER BY lastChange DESC
    """)

    files = []
    for row in cursor.fetchall():
        files.append({
            "filename": row[0],
            "size": row[1],
            "last_change": row[2],
            "resource_id": row[3],
            "parent_id": row[4],
            "etag": row[5]
        })

    conn.close()
    return files
```

## Cloud Storage Artifacts Summary

| Service | Local Database | Cache Location | Log Files |
|---------|---------------|----------------|-----------|
| OneDrive | SyncEngineDatabase.db | %LOCALAPPDATA%\Microsoft\OneDrive\cache\ | %LOCALAPPDATA%\Microsoft\OneDrive\logs\ |
| Google Drive | metadata_sqlite_db | %LOCALAPPDATA%\Google\DriveFS\{account}\content_cache\ | %LOCALAPPDATA%\Google\DriveFS\Logs\ |
| Dropbox | filecache.dbx (encrypted) | %APPDATA%\Dropbox\.dropbox.cache\ | %APPDATA%\Dropbox\logs\ |
| Box | sync_db | %LOCALAPPDATA%\Box\Box\cache\ | %LOCALAPPDATA%\Box\Box\logs\ |

## References

- SANS Cloud Storage Acquisition: https://www.sans.org/blog/cloud-storage-acquisition-from-endpoint-devices
- Magnet AXIOM Cloud: https://www.magnetforensics.com/blog/how-to-acquire-and-analyze-cloud-data-with-magnet-axiom/
- AWS Cloud Forensics Framework: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/cyber-forensics.html
- API-Based Forensic Acquisition of Cloud Drives: https://arxiv.org/abs/1603.06542

## Example Output

```text
$ python3 cloud_forensic_acquire.py --provider google-drive --auth /tokens/gdrive_token.json \
    --user jsmith@corporate.com --output /acquisition/gdrive

Cloud Storage Forensic Acquisition Tool v3.2
==============================================
Provider:    Google Drive
Account:     jsmith@corporate.com
Start Time:  2024-01-19 08:00:15 UTC
Auth Method: Admin SDK (domain-wide delegation)

[+] Enumerating files...
    Total files:        2,345
    Total folders:      178
    Shared with me:     456
    Trashed items:      89 (included in acquisition)
    Total size:         14.7 GB

[+] Acquiring file contents...
    Downloaded:    2,345 / 2,345  [████████████████████████████████] 100%
    Errors:        0
    Elapsed:       18m 32s

[+] Acquiring metadata...
    File metadata:      2,345 entries
    Revision history:   8,912 revisions across 1,234 files
    Sharing permissions: 3,456 permission entries
    Activity log:       12,345 events

[+] Acquiring trashed items...
    Recovered:     89 / 89 items (234 MB)

--- Acquisition Log ---
Timestamp (UTC)          | Action           | File                                    | Size    | SHA-256
2024-01-19 08:00:45      | Downloaded       | /My Drive/Finance/Q4_Report.xlsm        | 245 KB  | 7a3b8c9d...
2024-01-19 08:00:46      | Downloaded       | /My Drive/Finance/Budget_2024.xlsx       | 1.2 MB  | 8b4c9d0e...
...
2024-01-19 08:02:12      | Trash-Recovered  | /Trash/employee_list_full.csv            | 4.5 MB  | 9c5d0e1f...
2024-01-19 08:02:13      | Trash-Recovered  | /Trash/network_diagram_v3.vsdx          | 2.1 MB  | 0d6e1f2a...
2024-01-19 08:02:14      | Trash-Recovered  | /Trash/credentials_backup.kdbx          | 128 KB  | 1e7f2a3b...

--- Sharing Analysis ---
Files Shared Externally:
  /My Drive/Finance/Q4_Report.xlsm     → j.smith.personal8842@protonmail.com (2024-01-16 03:10 UTC)
  /My Drive/HR/employee_list_full.csv   → j.smith.personal8842@protonmail.com (2024-01-16 03:12 UTC)
  /My Drive/IT/network_diagram_v3.vsdx  → anonymous (link sharing, 2024-01-16 03:15 UTC)

--- Revision History (Suspicious) ---
File: /My Drive/Finance/Q4_Report.xlsm
  Rev 1:  2024-01-10 09:00:00 UTC  (245 KB)  - Original
  Rev 2:  2024-01-15 14:35:00 UTC  (248 KB)  - Modified (macro added)
  Rev 3:  2024-01-16 03:05:00 UTC  (245 KB)  - Reverted (macro removed - anti-forensics)

Acquisition Summary:
  Files acquired:       2,345 (14.7 GB)
  Trashed items:        89 (234 MB)
  Revisions:            8,912
  Chain of custody hash (full archive):
    SHA-256: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
  Output directory:     /acquisition/gdrive/
  Acquisition log:      /acquisition/gdrive/acquisition_log.csv
  Completion Time:      2024-01-19 08:18:47 UTC
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
