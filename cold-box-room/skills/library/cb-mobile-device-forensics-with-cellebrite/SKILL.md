---
name: cb-mobile-device-forensics-with-cellebrite
skill_id: cb-mobile-device-forensics-with-cellebrite
journal_id: CB-SKL-089
description: Cold-box analyst playbook — Mobile Device Forensics With Cellebrite.
  Acquire and analyze mobile device data using Cellebrite UFED and open-source tools
  to extract communications, location data, and application artifacts.
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
- mobile-forensics
- cellebrite
- smartphone-analysis
- ios-forensics
- android-forensics
cold_box_version: 2
inspired_by: performing-mobile-device-forensics-with-cellebrite
---

# Mobile Device Forensics With Cellebrite (cold-box)

> **Journal ID:** `CB-SKL-089` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-089`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-mobile-device-forensics-with-cellebrite")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-mobile-device-forensics-with-cellebrite")` → note **`CB-SKL-089`**
2. `log_skill(case_id, journal_id="CB-SKL-089", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-089` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When extracting evidence from smartphones or tablets during an investigation
- For recovering deleted messages, call logs, and location data from mobile devices
- During investigations involving communications via messaging apps
- When analyzing mobile application data for evidence of criminal activity
- For corporate investigations involving employee mobile device misuse

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `sha256sum` | `SIFT-018` | yes | yes |
| `sqlite3` | `SIFT-021` | yes | yes |
| `handle` | `SIFT-178` | no | no |
| `grep` | `SIFT-010` | yes | yes |
| `file` | `SIFT-008` | yes | yes |
| `tar` | `SIFT-003` | yes | yes |
| `dd` | `SIFT-034` | no | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] mmls per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] img_stat per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] sha256sum per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `sqlite3` → `SIFT-021`

```json
{
  "tool_id": "SIFT-021",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] sqlite3 per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] handle per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] grep per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] file per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

### `tar` → `SIFT-003`

```json
{
  "tool_id": "SIFT-003",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-089] tar per playbook step",
  "why": "Executing cb-mobile-device-forensics-with-cellebrite \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-089` (`cb-mobile-device-forensics-with-cellebrite`)

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
- When extracting evidence from smartphones or tablets during an investigation
- For recovering deleted messages, call logs, and location data from mobile devices
- During investigations involving communications via messaging apps
- When analyzing mobile application data for evidence of criminal activity
- For corporate investigations involving employee mobile device misuse

## Prerequisites
- Cellebrite UFED Touch/4PC or UFED Physical Analyzer (licensed)
- Alternative open-source tools: ALEAPP, iLEAPP, MEAT, libimobiledevice
- Appropriate cables and adapters for target device
- Faraday bag to isolate the device from network signals
- Legal authorization (warrant, consent, or corporate policy)
- Knowledge of iOS and Android file system structures

## Workflow

### Step 1: Prepare the Device and Isolation

```bash
# CRITICAL: Immediately place device in airplane mode or Faraday bag
# This prevents remote wipe commands and additional data changes

# Document device state before acquisition
# Record: make, model, IMEI, serial number, OS version, screen lock status
# Photograph the device from all angles

# For Android - Enable USB debugging if accessible
# Settings > Developer Options > USB Debugging > Enable

# For iOS - Trust the forensic workstation
# When prompted on device, tap "Trust This Computer"

# If device is locked, document lock type (PIN, pattern, biometric)
# Cellebrite UFED can bypass certain lock types depending on device model

# Install open-source tools as alternatives
pip install aleapp    # Android Logs Events And Protobuf Parser
pip install ileapp    # iOS Logs Events And Properties Parser
sudo apt-get install libimobiledevice-utils  # iOS acquisition on Linux
```

### Step 2: Perform Device Acquisition

```bash
# === Cellebrite UFED Acquisition ===
# 1. Launch UFED 4PC or connect UFED Touch
# 2. Select Device > Identify device model automatically
# 3. Choose extraction type:
#    - Logical: App data, contacts, messages, call logs (fastest, least data)
#    - File System: Full file system access including databases
#    - Physical: Bit-for-bit image including deleted data (most complete)
#    - Advanced (Checkm8/GrayKey): For locked iOS devices (specific models)
# 4. Select output format and destination
# 5. Begin extraction

# === Open-source iOS acquisition with libimobiledevice ===
# List connected iOS devices
idevice_id -l

# Get device information
ideviceinfo -u <UDID>

# Create iOS backup (logical acquisition)
idevicebackup2 backup --full /cases/case-2024-001/mobile/ios_backup/

# For encrypted backups (contains more data including passwords)
idevicebackup2 backup --full --password /cases/case-2024-001/mobile/ios_backup/

# === Android acquisition with ADB ===
# List connected devices
adb devices

# Full backup (requires screen unlock)
adb backup -apk -shared -all -f /cases/case-2024-001/mobile/android_backup.ab

# Extract specific app data
adb shell pm list packages | grep -i "whatsapp\|telegram\|signal"
adb pull /data/data/com.whatsapp/ /cases/case-2024-001/mobile/whatsapp/

# For rooted Android devices - full filesystem
adb shell "su -c 'dd if=/dev/block/mmcblk0 bs=4096'" | \
   dd of=/cases/case-2024-001/mobile/android_physical.dd

# Hash the acquisition
sha256sum /cases/case-2024-001/mobile/*.dd > /cases/case-2024-001/mobile/acquisition_hashes.txt
```

### Step 3: Analyze with ALEAPP (Android) or iLEAPP (iOS)

```bash
# === Android analysis with ALEAPP ===
# ALEAPP processes Android file system extractions
python3 -m aleapp \
   -t fs \
   -i /cases/case-2024-001/mobile/android_extraction/ \
   -o /cases/case-2024-001/analysis/aleapp_report/

# ALEAPP extracts and reports on:
# - Call logs, SMS/MMS messages
# - Chrome browser history and searches
# - WiFi connection history
# - Installed applications
# - Google account activity
# - Location data (Google Maps, Photos)
# - WhatsApp, Telegram, Signal messages
# - App usage statistics
# - Device settings and accounts

# === iOS analysis with iLEAPP ===
python3 -m ileapp \
   -t tar \
   -i /cases/case-2024-001/mobile/ios_backup.tar \
   -o /cases/case-2024-001/analysis/ileapp_report/

# iLEAPP extracts and reports on:
# - iMessage and SMS messages
# - Safari browsing history
# - WiFi and Bluetooth connections
# - Health data and location history
# - App usage (KnowledgeC)
# - Photos with EXIF/GPS data
# - Notes, Calendar, Reminders
# - Keychain data (if decryptable)
# - Screen time data
```

### Step 4: Extract Communications and Messaging Data

```bash
# Extract WhatsApp messages from Android
python3 << 'PYEOF'
import sqlite3
import os

# WhatsApp database location
db_path = "/cases/case-2024-001/mobile/android_extraction/data/data/com.whatsapp/databases/msgstore.db"

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Extract messages
    cursor.execute("""
        SELECT
            key_remote_jid AS contact,
            CASE WHEN key_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
            data AS message_text,
            datetime(timestamp/1000, 'unixepoch') AS msg_time,
            media_mime_type,
            media_size
        FROM messages
        WHERE data IS NOT NULL
        ORDER BY timestamp DESC
        LIMIT 1000
    """)

    with open('/cases/case-2024-001/analysis/whatsapp_messages.csv', 'w') as f:
        f.write("contact,direction,message,timestamp,media_type,media_size\n")
        for row in cursor.fetchall():
            f.write(','.join(str(x) for x in row) + '\n')

    conn.close()
    print("WhatsApp messages extracted successfully")
PYEOF

# Extract iOS iMessage/SMS from sms.db
python3 << 'PYEOF'
import sqlite3

db_path = "/cases/case-2024-001/mobile/ios_extraction/HomeDomain/Library/SMS/sms.db"

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("""
    SELECT
        h.id AS phone_number,
        CASE WHEN m.is_from_me = 1 THEN 'SENT' ELSE 'RECEIVED' END AS direction,
        m.text,
        datetime(m.date/1000000000 + 978307200, 'unixepoch') AS msg_time,
        m.service
    FROM message m
    JOIN handle h ON m.handle_id = h.ROWID
    ORDER BY m.date DESC
""")

with open('/cases/case-2024-001/analysis/imessage_sms.csv', 'w') as f:
    f.write("phone,direction,text,timestamp,service\n")
    for row in cursor.fetchall():
        f.write(','.join(str(x) for x in row) + '\n')

conn.close()
PYEOF
```

### Step 5: Extract Location Data and Generate Report

```bash
# Extract GPS data from photos
pip install pillow
python3 << 'PYEOF'
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import os, json

def get_gps(exif_data):
    gps_info = {}
    for key, val in exif_data.items():
        decoded = GPSTAGS.get(key, key)
        gps_info[decoded] = val

    if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
        lat = gps_info['GPSLatitude']
        lon = gps_info['GPSLongitude']
        lat_val = lat[0] + lat[1]/60 + lat[2]/3600
        lon_val = lon[0] + lon[1]/60 + lon[2]/3600
        if gps_info.get('GPSLatitudeRef') == 'S': lat_val = -lat_val
        if gps_info.get('GPSLongitudeRef') == 'W': lon_val = -lon_val
        return lat_val, lon_val
    return None

locations = []
photo_dir = "/cases/case-2024-001/mobile/ios_extraction/CameraRollDomain/Media/DCIM/"
for root, dirs, files in os.walk(photo_dir):
    for fname in files:
        if fname.lower().endswith(('.jpg', '.jpeg', '.heic')):
            try:
                img = Image.open(os.path.join(root, fname))
                exif = img._getexif()
                if exif and 34853 in exif:
                    coords = get_gps(exif[34853])
                    if coords:
                        locations.append({'file': fname, 'lat': coords[0], 'lon': coords[1]})
            except Exception:
                pass

with open('/cases/case-2024-001/analysis/photo_locations.json', 'w') as f:
    json.dump(locations, f, indent=2)
print(f"Found {len(locations)} geotagged photos")
PYEOF

# Extract location history from Google Location History (Android)
# File: /data/data/com.google.android.gms/databases/lbs.db
# or exported Google Takeout location data
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Logical extraction | Extracts accessible user data through device APIs (contacts, messages, photos) |
| File system extraction | Full access to the device file system including app databases |
| Physical extraction | Bit-for-bit copy of device storage including deleted and unallocated data |
| UFED | Universal Forensic Extraction Device - Cellebrite's flagship acquisition platform |
| ADB | Android Debug Bridge for communicating with Android devices |
| KnowledgeC | iOS database tracking detailed app and device usage patterns |
| SQLite databases | Primary storage format for mobile app data (messages, contacts, history) |
| Checkm8 | Hardware-based iOS exploit enabling extraction on A5-A11 devices |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Cellebrite UFED | Commercial mobile device acquisition and analysis platform |
| Cellebrite Physical Analyzer | Deep analysis of mobile device extractions |
| ALEAPP | Open-source Android artifact parser and report generator |
| iLEAPP | Open-source iOS artifact parser and report generator |
| libimobiledevice | Open-source iOS communication library |
| Magnet AXIOM | Commercial mobile and computer forensics platform |
| MEAT | Mobile Evidence Acquisition Toolkit |
| ADB | Android Debug Bridge for device interaction and data extraction |

## Common Scenarios

**Scenario 1: Criminal Communications Investigation**
Acquire device with UFED physical extraction, decrypt messaging databases, extract WhatsApp/Telegram/Signal conversations, recover deleted messages from WAL files, build communication timeline, export for legal proceedings.

**Scenario 2: Employee Data Theft via Personal Phone**
Perform logical extraction with employee consent, analyze corporate email and cloud storage app data, check for screenshots of confidential documents, review file transfer app activity, examine browser history for cloud uploads.

**Scenario 3: Missing Person Location Tracking**
Extract location data from Google Location History, parse GPS data from photos, analyze WiFi connection history for last known locations, check fitness app data for movement patterns, examine messaging apps for last communications.

**Scenario 4: Child Exploitation Investigation**
Physical extraction preserving all data including deleted content, hash all images against NCMEC/ICSE databases, extract communication records, recover deleted media from unallocated space, document chain of custody meticulously for prosecution.

## Output Format

```
Mobile Forensics Summary:
  Device: Samsung Galaxy S23 Ultra (SM-S918B)
  OS: Android 14, One UI 6.0
  IMEI: 353456789012345
  Extraction: Physical (via Cellebrite UFED)
  Duration: 45 minutes

  Extracted Data:
    Contacts:       1,234
    Call Logs:       5,678
    SMS/MMS:         3,456
    WhatsApp Msgs:   12,345 (234 deleted, recovered)
    Telegram Msgs:   2,345
    Photos/Videos:   4,567 (345 geotagged)
    Browser History: 2,345 URLs
    WiFi Networks:   67 saved connections
    Installed Apps:  145

  Key Findings:
    - Deleted WhatsApp conversation with suspect recovered
    - 23 geotagged photos at crime scene location
    - Browser searches related to investigation subject
    - Signal app used during incident timeframe (encrypted, partial recovery)

  Reports:
    ALEAPP Report:   /analysis/aleapp_report/index.html
    Messages Export: /analysis/whatsapp_messages.csv
    Locations:       /analysis/photo_locations.json
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
