---
name: cb-collecting-volatile-evidence-from-compromised-host
skill_id: cb-collecting-volatile-evidence-from-compromised-host
journal_id: CB-SKL-017
description: Cold-box analyst playbook — Collecting Volatile Evidence From Compromised
  Host. Collect volatile forensic evidence from a compromised system following order
  of volatility, preserving memory, network connections, processes, and system state
  before they are lost.
domain: cold-box
subdomain: incident-response
tier: core
case_profiles:
- memory
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- incident-response
- dfir
- forensics
- volatile-evidence
- memory-forensics
- chain-of-custody
cold_box_version: 2
inspired_by: collecting-volatile-evidence-from-compromised-host
---

# Collecting Volatile Evidence From Compromised Host (cold-box)

> **Journal ID:** `CB-SKL-017` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-017`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-collecting-volatile-evidence-from-compromised-host")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-collecting-volatile-evidence-from-compromised-host")` → note **`CB-SKL-017`**
2. `log_skill(case_id, journal_id="CB-SKL-017", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-017` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Security incident confirmed and compromised host identified
- Before system isolation, shutdown, or remediation begins
- Memory-resident malware suspected (fileless attacks)
- Need to capture network connections, running processes, and system state
- Legal proceedings may require forensic evidence preservation
- Incident requires root cause analysis with volatile data

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `sha256sum` | `SIFT-018` | yes | yes |
| `handle` | `SIFT-178` | no | no |
| `mount` | `SIFT-075` | no | yes |
| `grep` | `SIFT-010` | yes | yes |
| `tail` | `SIFT-023` | yes | yes |
| `lsof` | `SIFT-074` | yes | yes |
| `diff` | `SIFT-007` | yes | yes |
| `wmic` | `SIFT-186` | no | no |
| `file` | `SIFT-008` | yes | yes |
| `dd` | `SIFT-034` | no | yes |
| `tr` | `SIFT-024` | yes | yes |
| `ls` | `SIFT-014` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] powershell per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `sha256sum` → `SIFT-018`

```json
{
  "tool_id": "SIFT-018",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] sha256sum per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] handle per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `mount` → `SIFT-075`

```json
{
  "tool_id": "SIFT-075",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] mount per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `grep` → `SIFT-010`

```json
{
  "tool_id": "SIFT-010",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] grep per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `tail` → `SIFT-023`

```json
{
  "tool_id": "SIFT-023",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] tail per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `lsof` → `SIFT-074`

```json
{
  "tool_id": "SIFT-074",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] lsof per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

### `diff` → `SIFT-007`

```json
{
  "tool_id": "SIFT-007",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-017] diff per playbook step",
  "why": "Executing cb-collecting-volatile-evidence-from-compromised-host \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-017` (`cb-collecting-volatile-evidence-from-compromised-host`)

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
- Security incident confirmed and compromised host identified
- Before system isolation, shutdown, or remediation begins
- Memory-resident malware suspected (fileless attacks)
- Need to capture network connections, running processes, and system state
- Legal proceedings may require forensic evidence preservation
- Incident requires root cause analysis with volatile data

## Prerequisites
- Forensic collection toolkit on USB or network share (trusted tools)
- WinPmem/LiME for memory acquisition
- Write-blocker or forensic workstation for disk imaging
- Chain of custody documentation forms
- Secure evidence storage with integrity verification
- Authorization to collect evidence (legal/HR approval for insider cases)

## Workflow

### Step 1: Prepare Collection Environment
```bash
# Mount forensic USB toolkit (do NOT install tools on compromised system)
# Verify toolkit integrity
sha256sum /mnt/forensic_usb/tools/* > /tmp/toolkit_hashes.txt
diff /mnt/forensic_usb/tools/known_good_hashes.txt /tmp/toolkit_hashes.txt

# Create evidence output directory with timestamps
EVIDENCE_DIR="/mnt/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"
echo "Collection started: $(date -u)" > "$EVIDENCE_DIR/collection_log.txt"
echo "Collector: $(whoami)" >> "$EVIDENCE_DIR/collection_log.txt"
echo "System: $(hostname)" >> "$EVIDENCE_DIR/collection_log.txt"
```

### Step 2: Capture System Memory (Highest Volatility)
```bash
# Windows - WinPmem memory acquisition
winpmem_mini_x64.exe "$EVIDENCE_DIR\memdump_$(hostname).raw"

# Linux - LiME kernel module for memory acquisition
insmod /mnt/forensic_usb/lime.ko "path=$EVIDENCE_DIR/memdump_$(hostname).lime format=lime"

# Linux - Alternative using /proc/kcore
dd if=/proc/kcore of="$EVIDENCE_DIR/kcore_dump.raw" bs=1M

# macOS - osxpmem
osxpmem -o "$EVIDENCE_DIR/memdump_$(hostname).aff4"

# Hash the memory dump immediately
sha256sum "$EVIDENCE_DIR/memdump_"* > "$EVIDENCE_DIR/memory_hash.sha256"
```

### Step 3: Capture Network State
```bash
# Active network connections
# Windows
netstat -anob > "$EVIDENCE_DIR/netstat_connections.txt" 2>&1
Get-NetTCPConnection | Export-Csv "$EVIDENCE_DIR/tcp_connections.csv" -NoTypeInformation
Get-NetUDPEndpoint | Export-Csv "$EVIDENCE_DIR/udp_endpoints.csv" -NoTypeInformation

# Linux
ss -tulnp > "$EVIDENCE_DIR/socket_stats.txt"
netstat -anp > "$EVIDENCE_DIR/netstat_all.txt" 2>/dev/null
cat /proc/net/tcp > "$EVIDENCE_DIR/proc_net_tcp.txt"
cat /proc/net/udp > "$EVIDENCE_DIR/proc_net_udp.txt"

# ARP cache
arp -a > "$EVIDENCE_DIR/arp_cache.txt"

# Routing table
route print > "$EVIDENCE_DIR/routing_table.txt"  # Windows
ip route show > "$EVIDENCE_DIR/routing_table.txt"  # Linux

# DNS cache
ipconfig /displaydns > "$EVIDENCE_DIR/dns_cache.txt"  # Windows
# Linux: varies by resolver, check systemd-resolve or nscd
systemd-resolve --statistics > "$EVIDENCE_DIR/dns_stats.txt" 2>/dev/null

# Active firewall rules
netsh advfirewall show allprofiles > "$EVIDENCE_DIR/firewall_rules.txt"  # Windows
iptables -L -n -v > "$EVIDENCE_DIR/iptables_rules.txt"  # Linux
```

### Step 4: Capture Running Processes
```bash
# Windows - Detailed process list
tasklist /V /FO CSV > "$EVIDENCE_DIR/process_list_verbose.csv"
wmic process list full > "$EVIDENCE_DIR/wmic_process_full.txt"
Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet |
  Export-Csv "$EVIDENCE_DIR/ps_processes.csv" -NoTypeInformation

# Windows - Process with command line and parent
wmic process get ProcessId,Name,CommandLine,ParentProcessId,ExecutablePath /FORMAT:CSV > \
  "$EVIDENCE_DIR/process_commandlines.csv"

# Linux - Full process tree
ps auxwwf > "$EVIDENCE_DIR/process_tree.txt"
ps -eo pid,ppid,user,args --forest > "$EVIDENCE_DIR/process_forest.txt"
cat /proc/*/cmdline 2>/dev/null | tr '\0' ' ' > "$EVIDENCE_DIR/proc_cmdline_all.txt"

# Process modules/DLLs loaded
# Windows
listdlls.exe -accepteula > "$EVIDENCE_DIR/loaded_dlls.txt"
# Linux
for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
  echo "=== PID $pid ===" >> "$EVIDENCE_DIR/proc_maps.txt"
  cat "/proc/$pid/maps" 2>/dev/null >> "$EVIDENCE_DIR/proc_maps.txt"
done

# Open file handles
handle.exe -accepteula > "$EVIDENCE_DIR/open_handles.txt"  # Windows (Sysinternals)
lsof > "$EVIDENCE_DIR/open_files.txt"  # Linux
```

### Step 5: Capture Logged-in Users and Sessions
```bash
# Windows
query user > "$EVIDENCE_DIR/logged_in_users.txt"
query session > "$EVIDENCE_DIR/active_sessions.txt"
net session > "$EVIDENCE_DIR/net_sessions.txt" 2>&1
net use > "$EVIDENCE_DIR/mapped_drives.txt" 2>&1

# Linux
who > "$EVIDENCE_DIR/who_output.txt"
w > "$EVIDENCE_DIR/w_output.txt"
last -50 > "$EVIDENCE_DIR/last_logins.txt"
lastlog > "$EVIDENCE_DIR/lastlog.txt"
cat /var/log/auth.log | tail -200 > "$EVIDENCE_DIR/recent_auth.txt" 2>/dev/null
```

### Step 6: Capture System Configuration State
```bash
# System time (critical for timeline)
date -u > "$EVIDENCE_DIR/system_time_utc.txt"
w32tm /query /status > "$EVIDENCE_DIR/ntp_status.txt"  # Windows
ntpq -p > "$EVIDENCE_DIR/ntp_status.txt"  # Linux

# Environment variables
set > "$EVIDENCE_DIR/environment_vars.txt"  # Windows
env > "$EVIDENCE_DIR/environment_vars.txt"  # Linux

# Scheduled tasks / Cron jobs
schtasks /query /fo CSV /v > "$EVIDENCE_DIR/scheduled_tasks.csv"  # Windows
crontab -l > "$EVIDENCE_DIR/crontab_current.txt" 2>/dev/null  # Linux
ls -la /etc/cron.* > "$EVIDENCE_DIR/cron_dirs.txt" 2>/dev/null

# Services
sc queryex type=service state=all > "$EVIDENCE_DIR/services_all.txt"  # Windows
systemctl list-units --type=service --all > "$EVIDENCE_DIR/systemd_services.txt"  # Linux

# Windows Registry - key autostart locations
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "$EVIDENCE_DIR/reg_run_hklm.reg" /y
reg export "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "$EVIDENCE_DIR/reg_run_hkcu.reg" /y
reg export "HKLM\SYSTEM\CurrentControlSet\Services" "$EVIDENCE_DIR/reg_services.reg" /y
```

### Step 7: Hash All Evidence and Document Chain of Custody
```bash
# Generate SHA256 hashes for all collected evidence
cd "$EVIDENCE_DIR"
sha256sum * > evidence_manifest.sha256

# Create chain of custody record
cat > "$EVIDENCE_DIR/chain_of_custody.txt" << EOF
CHAIN OF CUSTODY RECORD
========================
Case ID: IR-YYYY-NNN
Collection Date: $(date -u)
Collected By: $(whoami)
System: $(hostname)
System IP: $(hostname -I 2>/dev/null || ipconfig | grep IPv4)
Collection Method: Live forensic collection via trusted USB toolkit

Evidence Items:
$(ls -la "$EVIDENCE_DIR/" | grep -v chain_of_custody)

SHA256 Manifest: evidence_manifest.sha256
Transfer: [TO BE COMPLETED]
Storage Location: [TO BE COMPLETED]
EOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Order of Volatility | RFC 3227 - Collect most volatile data first: registers > cache > memory > disk |
| Live Forensics | Collecting evidence from a running system before shutdown |
| Chain of Custody | Documentation tracking evidence handling from collection to court |
| Forensic Soundness | Ensuring evidence collection doesn't alter the original evidence |
| Trusted Tools | Using verified tools from external media, not from the compromised system |
| Evidence Integrity | SHA256 hashing of all evidence immediately after collection |
| Locard's Exchange Principle | Every contact leaves a trace - minimize investigator artifacts |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| WinPmem | Windows memory acquisition |
| LiME (Linux Memory Extractor) | Linux kernel memory acquisition |
| Sysinternals Suite | Process, handle, and DLL analysis (Windows) |
| Velociraptor | Remote forensic collection at scale |
| KAPE (Kroll Artifact Parser) | Automated artifact collection on Windows |
| CyLR | Cross-platform live response collection |
| GRR Rapid Response | Remote live forensics framework |

## Common Scenarios

1. **Fileless Malware Attack**: PowerShell-based attack with no files on disk. Memory dump is critical evidence containing the malicious scripts.
2. **Active C2 Session**: Attacker has live connection. Network connections and process data reveal C2 infrastructure.
3. **Insider Data Theft**: Employee copying files. Process list, mapped drives, and network connections show exfiltration activity.
4. **Compromised Web Server**: Web shell detected. Memory may contain additional backdoors not yet written to disk.
5. **Lateral Movement in Progress**: Attacker moving between systems. Authentication tokens and network sessions in memory reveal scope.

## Output Format
- Memory dump file (.raw or .lime format) with SHA256 hash
- Network state captures (connections, ARP, DNS, routes)
- Process listings with command lines and parent processes
- User session and authentication data
- System configuration snapshots
- Evidence manifest with SHA256 checksums
- Chain of custody documentation

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
