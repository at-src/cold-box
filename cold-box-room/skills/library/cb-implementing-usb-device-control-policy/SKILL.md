---
name: cb-implementing-usb-device-control-policy
skill_id: cb-implementing-usb-device-control-policy
journal_id: CB-SKL-289
description: Cold-box analyst playbook — Implementing Usb Device Control Policy. Implements
  USB device control policies to restrict unauthorized removable media access on endpoints,
  preventing data exfiltration and malware introduction via USB devices. Use when
  deploying device control via Group Policy, Intune, or EDR p
domain: cold-box
subdomain: endpoint-security
tier: adjacent
case_profiles:
- windows_usb
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- endpoint
- USB-control
- device-control
- data-loss-prevention
- removable-media
cold_box_version: 2
inspired_by: implementing-usb-device-control-policy
---

# Implementing Usb Device Control Policy (cold-box)

> **Journal ID:** `CB-SKL-289` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-289`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-implementing-usb-device-control-policy")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-implementing-usb-device-control-policy")` → note **`CB-SKL-289`**
2. `log_skill(case_id, journal_id="CB-SKL-289", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-289` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Restricting USB storage devices to prevent data exfiltration or malware introduction
- Implementing device control policies via GPO, Intune, or EDR device control modules
- Creating USB whitelists for authorized devices while blocking all others
- Meeting compliance requirements for removable media control (PCI DSS, HIPAA)

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
  "purpose": "[CB-SKL-289] powershell per playbook step",
  "why": "Executing cb-implementing-usb-device-control-policy \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-289] file per playbook step",
  "why": "Executing cb-implementing-usb-device-control-policy \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-289` (`cb-implementing-usb-device-control-policy`)

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
- Restricting USB storage devices to prevent data exfiltration or malware introduction
- Implementing device control policies via GPO, Intune, or EDR device control modules
- Creating USB whitelists for authorized devices while blocking all others
- Meeting compliance requirements for removable media control (PCI DSS, HIPAA)

**Do not use** for network-based DLP or cloud storage restrictions.

## Prerequisites

- Active Directory GPO or Microsoft Intune for policy deployment
- Device Instance IDs of authorized USB devices
- EDR with device control module (CrowdStrike, Microsoft Defender for Endpoint)
- Understanding of USB device classes (mass storage, HID, printer, etc.)

## Workflow

### Step 1: Inventory Current USB Usage

```powershell
# Enumerate currently connected USB devices
Get-PnpDevice -Class USB | Select-Object InstanceId, FriendlyName, Status

# Query USB storage history from registry
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" |
  Select-Object FriendlyName, ContainerID, HardwareID

# Collect USB usage across fleet (via EDR or scripts)
# CrowdStrike: Investigate → USB Device Activity
# MDE: DeviceEvents | where ActionType == "UsbDriveMounted"
```

### Step 2: Configure GPO Device Control

```
Computer Configuration → Administrative Templates → System → Removable Storage Access

- All Removable Storage classes: Deny all access → Enabled
  (Block read AND write for all removable storage)

OR for granular control:
- CD and DVD: Deny read access → Enabled
- Removable Disks: Deny write access → Enabled (read-only USB)
- Tape Drives: Deny all access → Enabled
- WPD Devices: Deny all access → Enabled

To allow specific approved USB devices:
Computer Configuration → Administrative Templates → System → Device Installation
  → Device Installation Restrictions

- Prevent installation of devices not described by other policy settings → Enabled
- Allow installation of devices that match any of these device IDs → Enabled
  Add approved Device IDs: USB\VID_0781&PID_5583 (example: SanDisk Cruzer)
```

### Step 3: Deploy via Microsoft Defender for Endpoint

```xml
<!-- MDE Device Control policy (XML format) -->
<PolicyGroups>
  <Group Id="{d9a81dc0-1234-5678-9abc-def012345678}"
    Type="Device" Name="Approved USB Devices">
    <MatchClause>
      <MatchType>VID_PID</MatchType>
      <MatchData>0781_5583</MatchData> <!-- SanDisk -->
    </MatchClause>
  </Group>
</PolicyGroups>

<PolicyRules>
  <Rule Id="{rule-guid}" Name="Block unapproved USB storage">
    <IncludedIdList>
      <PrimaryId>RemovableMediaDevices</PrimaryId>
    </IncludedIdList>
    <ExcludedIdList>
      <GroupId>{d9a81dc0-1234-5678-9abc-def012345678}</GroupId>
    </ExcludedIdList>
    <Entry>
      <Type>Deny</Type>
      <AccessMask>63</AccessMask> <!-- All access -->
      <Options>4</Options> <!-- Show notification -->
    </Entry>
  </Rule>
</PolicyRules>
```

### Step 4: Audit and Monitor

```
# Monitor USB events in SIEM:
# Windows Event ID 6416 - New external device recognized
# Windows Event ID 4663 - File access on removable media
# MDE: DeviceEvents where ActionType contains "Usb"

# Generate USB activity reports monthly
# Track: blocked attempts, approved device usage, exception requests
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **VID/PID** | Vendor ID and Product ID that uniquely identify USB device models |
| **Device Instance ID** | Unique identifier for a specific physical USB device |
| **Device Control** | EDR/endpoint feature restricting device access based on type, vendor, or serial number |
| **USB Class** | USB device category (mass storage 08h, HID 03h, printer 07h) |

## Tools & Systems

- **Microsoft Defender Device Control**: MDE module for USB restriction policies
- **CrowdStrike Falcon Device Control**: EDR-based USB policy enforcement
- **Group Policy (Removable Storage Access)**: Built-in Windows USB restriction via GPO
- **Endpoint Protector**: Third-party device control and DLP solution

## Common Pitfalls

- **Blocking all USB without exception**: Keyboards and mice are USB HID devices. Block only mass storage class, not all USB.
- **Not communicating policy to users**: USB blocks without user notification generate helpdesk tickets. Display a notification explaining the policy.
- **Ignoring USB-C and Thunderbolt**: Modern devices use USB-C for docking, charging, and storage. Policies must distinguish between USB storage and USB peripherals.
- **No approved device process**: Users with legitimate USB needs (presentations, field data collection) require an exception process with approved, encrypted devices.

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
