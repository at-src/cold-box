---
name: cb-deploying-edr-agent-with-crowdstrike
skill_id: cb-deploying-edr-agent-with-crowdstrike
journal_id: CB-SKL-170
description: Cold-box analyst playbook — Deploying Edr Agent With Crowdstrike. Deploys
  and configures CrowdStrike Falcon EDR agents across enterprise endpoints to enable
  real-time threat detection, behavioral analysis, and automated response. Use when
  onboarding endpoints to EDR coverage, configuring detection policie
domain: cold-box
subdomain: endpoint-security
tier: adjacent
case_profiles:
- soc_siem
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- endpoint
- edr
- CrowdStrike
- Falcon
- threat-detection
- sensor-deployment
cold_box_version: 2
inspired_by: deploying-edr-agent-with-crowdstrike
---

# Deploying Edr Agent With Crowdstrike (cold-box)

> **Journal ID:** `CB-SKL-170` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-170`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-deploying-edr-agent-with-crowdstrike")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-deploying-edr-agent-with-crowdstrike")` → note **`CB-SKL-170`**
2. `log_skill(case_id, journal_id="CB-SKL-170", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-170` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Deploying CrowdStrike Falcon sensors to Windows, macOS, or Linux endpoints
- Configuring Falcon prevention and detection policies for different endpoint groups
- Integrating CrowdStrike telemetry with SIEM (Splunk, Elastic, Sentinel) for correlated detection
- Troubleshooting sensor connectivity, performance, or detection issues

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-170] powershell per playbook step",
  "why": "Executing cb-deploying-edr-agent-with-crowdstrike \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-170] file per playbook step",
  "why": "Executing cb-deploying-edr-agent-with-crowdstrike \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-170` (`cb-deploying-edr-agent-with-crowdstrike`)

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

Use this skill when:
- Deploying CrowdStrike Falcon sensors to Windows, macOS, or Linux endpoints
- Configuring Falcon prevention and detection policies for different endpoint groups
- Integrating CrowdStrike telemetry with SIEM (Splunk, Elastic, Sentinel) for correlated detection
- Troubleshooting sensor connectivity, performance, or detection issues

**Do not use** this skill for deploying other EDR solutions (Carbon Black, SentinelOne) or for Falcon cloud workload protection (use cloud-specific deployment guides).

## Prerequisites

- CrowdStrike Falcon console access with Falcon Administrator role
- Customer ID (CID) and Falcon sensor installer package
- Administrative/root access on target endpoints
- Network access: endpoints must reach CrowdStrike cloud (ts01-b.cloudsink.net on port 443)
- Deployment tool: SCCM, Intune, GPO, Ansible, or manual installation

## Workflow

### Step 1: Obtain Falcon Sensor Installer and CID

```
1. Log into Falcon Console: https://falcon.crowdstrike.com
2. Navigate: Host setup and management → Sensor downloads
3. Download the appropriate installer:
   - Windows: WindowsSensor_<version>.exe
   - macOS: FalconSensorMacOS_<version>.pkg
   - Linux: falcon-sensor_<version>_amd64.deb / .rpm
4. Copy the Customer ID (CID) from the Sensor downloads page
   - CID format: <32-char-hex>-<2-char-checksum>
```

### Step 2: Deploy Falcon Sensor - Windows

**Silent installation via command line**:
```cmd
WindowsSensor_7.18.17106.exe /install /quiet /norestart CID=<YOUR_CID>
```

**SCCM deployment**:
```
1. Create an Application in SCCM
2. Deployment type: Script Installer
3. Install command: WindowsSensor_7.18.17106.exe /install /quiet /norestart CID=<CID>
4. Detection method: Registry key exists
   - HKLM\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default
5. Deploy to target collection
6. Deployment purpose: Required (for mandatory installation)
```

**Microsoft Intune deployment**:
```
1. Navigate: Devices → Windows → Configuration profiles
2. Create Win32 app deployment
3. Upload .intunewin package (wrapped sensor installer)
4. Install command: WindowsSensor_7.18.17106.exe /install /quiet /norestart CID=<CID>
5. Detection rule: File exists C:\Windows\System32\drivers\CrowdStrike\csagent.sys
6. Assign to device group
```

**GPO deployment**:
```powershell
# Create startup script that checks for existing installation
$sensorPath = "C:\Windows\System32\drivers\CrowdStrike\csagent.sys"
if (-not (Test-Path $sensorPath)) {
    Start-Process -FilePath "\\fileserver\CrowdStrike\WindowsSensor.exe" `
      -ArgumentList "/install /quiet /norestart CID=<CID>" -Wait
}
```

### Step 3: Deploy Falcon Sensor - Linux

```bash
# Debian/Ubuntu
sudo dpkg -i falcon-sensor_7.18.0-17106_amd64.deb
sudo /opt/CrowdStrike/falconctl -s -f --cid=<YOUR_CID>
sudo systemctl start falcon-sensor
sudo systemctl enable falcon-sensor

# RHEL/CentOS
sudo yum install falcon-sensor-7.18.0-17106.el8.x86_64.rpm
sudo /opt/CrowdStrike/falconctl -s -f --cid=<YOUR_CID>
sudo systemctl start falcon-sensor
sudo systemctl enable falcon-sensor

# Verify sensor is running and connected
sudo /opt/CrowdStrike/falconctl -g --rfm-state
# Expected output: rfm-state=false (sensor is communicating with cloud)
```

### Step 4: Deploy Falcon Sensor - macOS

```bash
# Install sensor package
sudo installer -pkg FalconSensorMacOS_7.18.pkg -target /

# Set CID
sudo /Applications/Falcon.app/Contents/Resources/falconctl license <YOUR_CID>

# Grant Full Disk Access and System Extension via MDM profile
# Required for macOS Ventura+ (manual approval or MDM PPPC profile)
# MDM payload: com.crowdstrike.falcon.Agent → SystemExtension + Full Disk Access

# Verify sensor status
sudo /Applications/Falcon.app/Contents/Resources/falconctl stats
```

### Step 5: Configure Prevention Policies

In Falcon Console, navigate to Configuration → Prevention Policies:

**Recommended prevention policy settings**:
```
Machine Learning:
  - Cloud ML: Aggressive (extra protection, may increase false positives)
  - Sensor ML: Moderate
  - Adware & PUP: Moderate

Behavioral Protection:
  - On Write: Enabled (detect malware on file creation)
  - On Sensor ML: Enabled
  - Interpreter-Only: Enabled (detect script-based attacks)

Exploit Mitigation:
  - Exploit behavior protection: Enabled
  - Memory scanning: Enabled (detects in-memory attacks)
  - Code injection: Enabled

Ransomware:
  - Ransomware protection: Enabled
  - Shadow copy protection: Enabled
  - MBR protection: Enabled
```

**Create separate policies for**:
- Workstations (aggressive settings)
- Servers (moderate settings to avoid false positives on server workloads)
- Critical infrastructure (maximum protection with exception lists)

### Step 6: Configure Response Policies

```
Real-Time Response:
  - Enable RTR for all sensor groups
  - Configure RTR admin vs. RTR responder roles
  - Enable script execution (for IR teams)
  - Enable file extraction (for forensics)

Network Containment:
  - Pre-authorize containment for specific host groups
  - Configure containment exclusions (allow management traffic)

Automated Response:
  - Enable automated remediation for high-confidence detections
  - Configure kill process action for ransomware detections
  - Enable quarantine for malware file detections
```

### Step 7: Validate Deployment

```powershell
# Windows: Check Falcon sensor status
sc query csagent
# Expected: RUNNING

# Check sensor version
reg query "HKLM\SYSTEM\CrowdStrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default" /v AgentVersion

# Verify cloud connectivity
# In Falcon Console: Host Management → Hosts → search for hostname
# Status should show "Online" with last seen timestamp < 5 minutes
```

**Test detection capability**:
```powershell
# CrowdStrike provides test detection samples
# Download CsTestDetect.exe from Falcon Console → Host setup
# Run on endpoint to generate a test detection
.\CsTestDetect.exe
# Verify detection appears in Falcon Console within 60 seconds
```

### Step 8: SIEM Integration

```
# Falcon SIEM Connector (Streaming API)
# Configure in Falcon Console: Support → API Clients and Keys

# Create API client with scope: Event Streams → Read
# Use falcon-siem-connector or Falcon Data Replicator (FDR)

# Splunk integration:
# Install CrowdStrike Falcon Event Streams Technical Add-on from Splunkbase
# Configure: Settings → Data inputs → CrowdStrike Falcon Event Streams
# Enter API Client ID and Secret
# Index: crowdstrike_events

# Elastic integration:
# Use Elastic Agent with CrowdStrike module
# Configure: Fleet → Agent policies → Add integration → CrowdStrike
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **Falcon Sensor** | Lightweight kernel-mode agent (25-30 MB) that collects endpoint telemetry and enforces prevention policies |
| **CID (Customer ID)** | Unique identifier that associates the sensor with your CrowdStrike Falcon tenant |
| **RFM (Reduced Functionality Mode)** | State where sensor operates with limited capability due to cloud connectivity loss |
| **Sensor Grouping Tags** | Labels applied during installation to auto-assign hosts to groups and policies |
| **RTR (Real-Time Response)** | Remote shell capability for incident responders to interact with endpoints through Falcon |
| **IOA (Indicators of Attack)** | Behavioral detections based on adversary techniques rather than static signatures |

## Tools & Systems

- **CrowdStrike Falcon Console**: Cloud-hosted management platform for all Falcon modules
- **Falcon SIEM Connector**: Streams detection and audit events to SIEM platforms
- **Falcon Data Replicator (FDR)**: Streams raw endpoint telemetry to S3/cloud storage for hunting
- **CrowdStrike Falcon API (OAuth2)**: RESTful API for automation, integration, and custom workflows
- **PSFalcon**: PowerShell module for CrowdStrike Falcon API automation

## Common Pitfalls

- **Missing CID during installation**: Sensor installs but never connects to Falcon cloud. Always pass CID during install, not after.
- **Proxy not configured**: In environments with web proxies, configure proxy during installation: `/install /quiet CID=<CID> APP_PROXYNAME=proxy.corp.com APP_PROXYPORT=8080`.
- **macOS System Extension blocked**: macOS requires explicit approval for kernel/system extensions. Use MDM to pre-approve CrowdStrike extensions before deployment.
- **Conflicting security products**: Running multiple EDR/AV products causes performance issues and false positives. Coordinate exclusions or remove legacy AV before Falcon deployment.
- **Sensor version pinning**: Falcon auto-updates sensors by default. Pin sensor versions in the console for change-controlled environments before testing new versions.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
