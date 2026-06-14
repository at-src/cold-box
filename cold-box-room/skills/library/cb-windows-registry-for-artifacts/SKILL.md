---
name: cb-windows-registry-for-artifacts
skill_id: cb-windows-registry-for-artifacts
journal_id: CB-SKL-122
description: Cold-box analyst playbook — Windows Registry For Artifacts. Extract and
  analyze Windows Registry hives to uncover user activity, installed software, autostart
  entries, and evidence of system compromise.
domain: cold-box
subdomain: digital-forensics
tier: core
case_profiles:
- windows_disk
execution_mode: sift_runnable
artifact_platforms:
- windows
host_platforms:
- linux
tags:
- forensics
- windows-registry
- artifact-analysis
- regripper
- registry-explorer
- evidence-collection
cold_box_version: 2
inspired_by: analyzing-windows-registry-for-artifacts
---

# Windows Registry For Artifacts (cold-box)

> **Journal ID:** `CB-SKL-122` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **`get_skill`** auto-records playbook adoption — do not `log_skill(adopted)`.
- **`run_sift_tool` / `analyze_scratch`** auto-record `audit_id` in audit log + journal — never cite IDs in report text.
- Optional **`log_skill(action=finding|corrected)`** for analyst conclusions only (no audit IDs).
- Prefer tools with `do_not_use` unset; `not_verified` only means not lab auto-tested — check `runnable` and `describe_sift_tool`.
- Load this playbook with `get_skill("cb-windows-registry-for-artifacts")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-windows-registry-for-artifacts")` → harness logs **`CB-SKL-122`**
2. `list_sift_tools(verified_only=true)` → pick tools from the map below
3. `describe_sift_tool(tool_id)` → `run_sift_tool(..., journal_id="CB-SKL-122")` → read scratch preview
4. `analyze_scratch` on scratch when needed; optional `log_skill(..., action="finding")` for conclusions
5. `submit_report` — plain language only; harness appends grounded audit table


## When to use

- When investigating user activity on a Windows system during an incident
- For identifying autorun/persistence mechanisms used by malware
- When tracing installed software, USB devices, and network connections
- During insider threat investigations to reconstruct user actions
- For correlating registry timestamps with other forensic artifacts

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `mmls` | `SIFT-160` | no | yes |
| `img_stat` | `SIFT-154` | yes | yes |
| `AppCompatCacheParser` | `SIFT-190` | yes | yes |
| `AmcacheParser` | `SIFT-188` | yes | yes |
| `sha256sum` | `SIFT-018` | yes | yes |
| `rip.pl` | `SIFT-098` | yes | yes |
| `mount` | `SIFT-075` | no | yes |
| `RECmd` | `SIFT-224` | yes | yes |
| `icat` | `SIFT-151` | yes | yes |
| `fls` | `SIFT-148` | yes | yes |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `mmls` → `SIFT-160`

```json
{
  "tool_id": "SIFT-160",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] mmls per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `img_stat` → `SIFT-154`

```json
{
  "tool_id": "SIFT-154",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] img_stat per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `AppCompatCacheParser` → `SIFT-190`

```json
{
  "tool_id": "SIFT-190",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] AppCompatCacheParser per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `AmcacheParser` → `SIFT-188`

```json
{
  "tool_id": "SIFT-188",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] AmcacheParser per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] sha256sum per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `rip.pl` → `SIFT-098`

```json
{
  "tool_id": "SIFT-098",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] rip.pl per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] mount per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

### `RECmd` → `SIFT-224`

```json
{
  "tool_id": "SIFT-224",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-122] RECmd per playbook step",
  "why": "Executing cb-windows-registry-for-artifacts \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

Harness-owned (you do not write audit IDs):

- **`get_skill`** → journal `adopted` for **`CB-SKL-122`**
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

## Cold-box sealed E01 workflow (registry hives)

When evidence is a sealed E01/DD on the operation table:

1. **Navigate** — `fls` (SIFT-148) with `-o OFFSET` to user profile (`NTUSER.DAT`) and `Windows/System32/config/` (SAM, SYSTEM, SOFTWARE).
2. **Extract** — `icat` (SIFT-151, `output_style: inode_stream`): `extra_args: ["-o", OFFSET, "INODE"]` for each hive.
3. **Parse** — `analyze_scratch` on scratch extracts: `strings`/`grep` for keys of interest, or RECmd/regripper if run against scratch copies per tool map.
4. **Journal** — `CB-SKL-122` + audit IDs on each step.

Read `describe_sift_tool` for catalog fields (`output_style`, `runnable`, `common_flags`).

## When to Use
- When investigating user activity on a Windows system during an incident
- For identifying autorun/persistence mechanisms used by malware
- When tracing installed software, USB devices, and network connections
- During insider threat investigations to reconstruct user actions
- For correlating registry timestamps with other forensic artifacts

## Prerequisites
- Forensic image or extracted registry hive files
- RegRipper, Registry Explorer (Eric Zimmerman), or python-registry
- Access to registry hive locations (SAM, SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat)
- Understanding of Windows Registry structure (hives, keys, values)
- SIFT Workstation or forensic analysis environment

## Workflow

### Step 1: Extract Registry Hives from the Forensic Image

```bash
# Mount the forensic image read-only
mkdir /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Copy system registry hives
cp /mnt/evidence/Windows/System32/config/SAM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SECURITY /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/DEFAULT /cases/case-2024-001/registry/

# Copy user-specific hives
cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/registry/
cp /mnt/evidence/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat /cases/case-2024-001/registry/

# Copy transaction logs (for dirty hive recovery)
cp /mnt/evidence/Windows/System32/config/*.LOG* /cases/case-2024-001/registry/logs/

# Hash all extracted hives
sha256sum /cases/case-2024-001/registry/* > /cases/case-2024-001/registry/hive_hashes.txt
```

### Step 2: Analyze with RegRipper for Automated Artifact Extraction

```bash
# Install RegRipper
git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper

# Run RegRipper against NTUSER.DAT (user profile)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -f ntuser > /cases/case-2024-001/analysis/ntuser_report.txt

# Run against SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -f system > /cases/case-2024-001/analysis/system_report.txt

# Run against SOFTWARE hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -f software > /cases/case-2024-001/analysis/software_report.txt

# Run against SAM hive (user accounts)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SAM \
   -f sam > /cases/case-2024-001/analysis/sam_report.txt

# Run specific plugins
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p userassist > /cases/case-2024-001/analysis/userassist.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p usbstor > /cases/case-2024-001/analysis/usbstor.txt
```

### Step 3: Extract Persistence and Autorun Entries

```bash
# Using python-registry for targeted extraction
pip install python-registry

python3 << 'PYEOF'
from Registry import Registry

# Open SOFTWARE hive
reg = Registry.Registry("/cases/case-2024-001/registry/SOFTWARE")

# Check Run keys (autostart)
autorun_paths = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for path in autorun_paths:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass

# Check installed services
key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Svchost")
print(f"\n=== Svchost Groups ===")
for value in key.values():
    print(f"  {value.name()}: {value.value()}")
PYEOF

# Check NTUSER.DAT for user-specific autorun
python3 << 'PYEOF'
from Registry import Registry

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

user_autorun = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
]

for path in user_autorun:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass
PYEOF
```

### Step 4: Analyze User Activity Artifacts

```bash
# Extract UserAssist data (program execution history with ROT13 encoding)
python3 << 'PYEOF'
from Registry import Registry
import codecs, struct, datetime

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
key = reg.open(ua_path)

for guid_key in key.subkeys():
    count_key = guid_key.subkey("Count")
    print(f"\n=== {guid_key.name()} ===")
    for value in count_key.values():
        decoded_name = codecs.decode(value.name(), 'rot_13')
        data = value.value()
        if len(data) >= 16:
            run_count = struct.unpack('<I', data[4:8])[0]
            focus_count = struct.unpack('<I', data[8:12])[0]
            timestamp = struct.unpack('<Q', data[60:68])[0] if len(data) >= 68 else 0
            if timestamp > 0:
                ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=timestamp//10)
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}, Last={ts}")
            else:
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}")
PYEOF

# Extract Recent Documents (MRU lists)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p recentdocs > /cases/case-2024-001/analysis/recentdocs.txt

# Extract typed URLs (browser)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedurls > /cases/case-2024-001/analysis/typedurls.txt

# Extract typed paths in Explorer
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedpaths > /cases/case-2024-001/analysis/typedpaths.txt
```

### Step 5: Extract System and Network Information

```bash
# Computer name and OS version from SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p compname > /cases/case-2024-001/analysis/system_info.txt

# Network interfaces and configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p nic2 >> /cases/case-2024-001/analysis/system_info.txt

# Wireless network history
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p networklist > /cases/case-2024-001/analysis/network_history.txt

# Timezone configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p timezone > /cases/case-2024-001/analysis/timezone.txt

# Shutdown time
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p shutdown > /cases/case-2024-001/analysis/shutdown.txt

# Installed software from Uninstall keys
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p uninstall > /cases/case-2024-001/analysis/installed_software.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Registry hive | Binary file storing a section of the registry (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) |
| MRU (Most Recently Used) | Lists tracking recently accessed files, commands, and search terms |
| UserAssist | ROT13-encoded registry entries tracking program execution with timestamps |
| ShimCache | Application compatibility cache recording executed programs |
| AmCache | Detailed execution history including SHA-1 hashes of executables |
| BAM/DAM | Background/Desktop Activity Moderator tracking program execution in Win10+ |
| Last Write Time | Timestamp on registry keys indicating when they were last modified |
| Transaction logs | Journal files allowing recovery of registry state after improper shutdown |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RegRipper | Automated registry artifact extraction with plugin architecture |
| Registry Explorer | Eric Zimmerman GUI tool for interactive registry analysis |
| python-registry | Python library for programmatic registry hive parsing |
| RECmd | Eric Zimmerman command-line registry analysis tool |
| yarp | Yet Another Registry Parser for Python-based analysis |
| AppCompatCacheParser | Dedicated ShimCache/AppCompatCache parser |
| AmcacheParser | Dedicated AmCache.hve analysis tool |
| ShellBags Explorer | Specialized tool for analyzing ShellBag artifacts |

## Common Scenarios

**Scenario 1: Malware Persistence Investigation**
Extract SOFTWARE and NTUSER.DAT hives, check all Run/RunOnce keys for unauthorized entries, examine services for suspicious additions, check scheduled tasks registry keys, correlate autorun timestamps with malware execution timeline.

**Scenario 2: User Activity Reconstruction**
Analyze UserAssist for program execution history, examine RecentDocs for accessed files, check TypedPaths for Explorer navigation, extract ShellBags for folder access patterns, build a timeline of user activity around the incident window.

**Scenario 3: Unauthorized Software Detection**
Parse Uninstall keys for all installed applications, compare against approved software baseline, check BAM/DAM for recently executed programs not in approved list, examine AppCompatCache for execution evidence even after uninstallation.

**Scenario 4: USB Data Exfiltration Investigation**
Extract USBSTOR entries from SYSTEM hive for connected devices, correlate device serial numbers with MountedDevices, check NTUSER.DAT MountPoints2 for user access to removable media, examine SetupAPI logs for first-connection timestamps.

## Output Format

```
Registry Analysis Summary:
  System: DESKTOP-ABC123 (Windows 10 Pro Build 19041)
  Timezone: Eastern Standard Time (UTC-5)
  Last Shutdown: 2024-01-18 23:45:12 UTC

  Autorun Entries:
    HKLM Run:     5 entries (1 suspicious: "updater.exe" -> C:\ProgramData\svc\updater.exe)
    HKCU Run:     3 entries (all legitimate)
    Services:     142 entries (2 unknown: "WinDefSvc", "SysMonAgent")

  User Activity (NTUSER.DAT):
    UserAssist Programs:  234 entries
    Recent Documents:     89 entries
    Typed URLs:           45 entries
    Typed Paths:          12 entries

  USB Devices Connected:
    - Kingston DataTraveler (Serial: 0019E06B4521) - First: 2024-01-10, Last: 2024-01-18
    - WD My Passport (Serial: 575834314131) - First: 2024-01-15, Last: 2024-01-15

  Installed Software:     127 applications
  Suspicious Findings:    3 items flagged for review
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
