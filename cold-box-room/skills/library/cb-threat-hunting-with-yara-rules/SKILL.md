---
name: cb-threat-hunting-with-yara-rules
skill_id: cb-threat-hunting-with-yara-rules
journal_id: CB-SKL-112
description: Cold-box analyst playbook — Threat Hunting With Yara Rules. Use YARA
  pattern-matching rules to hunt for malware, suspicious files, and indicators of
  compromise across filesystems and memory dumps. Covers rule authoring, yara-python
  scanning, and integration with threat intel feeds.
domain: cold-box
subdomain: threat-hunting
tier: core
case_profiles:
- threat_intel
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- yara
- malware-detection
- threat-hunting
- pattern-matching
cold_box_version: 2
inspired_by: performing-threat-hunting-with-yara-rules
---

# Threat Hunting With Yara Rules (cold-box)

> **Journal ID:** `CB-SKL-112` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-112`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-threat-hunting-with-yara-rules")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-threat-hunting-with-yara-rules")` → note **`CB-SKL-112`**
2. `log_skill(case_id, journal_id="CB-SKL-112", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-112` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- Proactively hunting for unknown malware variants across network shares, endpoints, and email attachments
- Scanning quarantine directories or sandbox outputs for malware family classification
- Searching process memory dumps for injected code or in-memory-only payloads
- Validating threat intelligence IOCs against a large corpus of collected samples
- Triaging incident response artifacts to identify known malware families quickly
- Building automated detection pipelines that scan new files on ingestion

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `strings` | `SIFT-044` | yes | yes |
| `yara` | `SIFT-045` | no | no |
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `powershell` → `SIFT-179`

```json
{
  "tool_id": "SIFT-179",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-112] powershell per playbook step",
  "why": "Executing cb-threat-hunting-with-yara-rules \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-112] strings per playbook step",
  "why": "Executing cb-threat-hunting-with-yara-rules \u2014 see Procedure section",
  "extra_args": []
}
```

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-112] yara per playbook step",
  "why": "Executing cb-threat-hunting-with-yara-rules \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-112] file per playbook step",
  "why": "Executing cb-threat-hunting-with-yara-rules \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-112` (`cb-threat-hunting-with-yara-rules`)

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

Scan files, directories, and memory dumps using YARA rules to identify
malware families, suspicious patterns, and IOC matches.

## When to Use

- Proactively hunting for unknown malware variants across network shares, endpoints, and email attachments
- Scanning quarantine directories or sandbox outputs for malware family classification
- Searching process memory dumps for injected code or in-memory-only payloads
- Validating threat intelligence IOCs against a large corpus of collected samples
- Triaging incident response artifacts to identify known malware families quickly
- Building automated detection pipelines that scan new files on ingestion

**Do not use** for real-time endpoint protection (use EDR agents instead); YARA scanning is best suited for batch hunting, triage, and post-collection analysis where scan latency is acceptable.

## Prerequisites

- YARA 4.x installed (`apt install yara` on Debian/Ubuntu, `brew install yara` on macOS)
- Python 3.8+ with `yara-python` (`pip install yara-python`)
- `yarGen` for automated rule generation (`git clone https://github.com/Neo23x0/yarGen`)
- Sample malware corpus or suspicious files for scanning (from malware zoos, VT, or incident artifacts)
- Optional: `pefile` for PE header analysis, `malduck` for memory carving
- Threat intel YARA rule sets (e.g., YARA-Rules community repository, Florian Roth signature-base)

## Workflow

### Step 1: Install YARA and Python Bindings

```bash
# Linux
sudo apt update && sudo apt install -y yara

# Python bindings
pip install yara-python

# Verify installation
yara --version
python3 -c "import yara; print(yara.YARA_VERSION)"
```

### Step 2: Write a Basic YARA Rule

Create rules that match on strings, hex patterns, and file metadata:

```yara
// File: rules/emotet_loader.yar
rule Emotet_Loader_2026 {
    meta:
        author = "Threat Intel Team"
        description = "Detects Emotet first-stage loader DLL"
        date = "2026-01-20"
        reference = "https://attack.mitre.org/software/S0367/"
        mitre_attack = "T1059.001, T1055.001"
        severity = "critical"

    strings:
        // Emotet export function name patterns
        $export1 = "DllRegisterServer" ascii
        $export2 = "RunDLL" ascii nocase

        // Obfuscated string decryption routine
        $decrypt_loop = { 8B 45 ?? 33 45 ?? 89 45 ?? 8B 4D ?? 03 4D ?? }

        // PowerShell download cradle in embedded script
        $ps_cradle = /powershell[^\n]{0,50}-e(nc|ncodedcommand)/i

        // Known C2 URI patterns
        $uri1 = "/wp-content/uploads/" ascii
        $uri2 = "/wp-admin/css/" ascii
        $uri3 = "/wp-includes/" ascii

        // PE characteristics
        $mz = "MZ" at 0

    condition:
        $mz and
        filesize < 2MB and
        (
            ($export1 and $decrypt_loop) or
            ($ps_cradle and any of ($uri*)) or
            (2 of ($uri*) and $decrypt_loop)
        )
}
```

### Step 3: Write Advanced Rules with Modules

Use YARA modules for PE header inspection and math-based entropy checks:

```yara
import "pe"
import "math"

rule Suspicious_Packed_Executable {
    meta:
        author = "Threat Hunting Team"
        description = "Detects PE files with high entropy sections indicating packing or encryption"
        severity = "medium"

    condition:
        pe.is_pe and
        pe.number_of_sections > 0 and
        for any section in pe.sections : (
            math.entropy(section.offset, section.size) > 7.2 and
            section.size > 1024
        ) and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "VirtualProtect")
}

rule Suspicious_UPX_Modified {
    meta:
        description = "Detects UPX-packed binaries with tampered section names"
        severity = "medium"

    strings:
        $upx_magic = { 55 50 58 21 }  // UPX!

    condition:
        pe.is_pe and
        $upx_magic and
        not (
            pe.sections[0].name == "UPX0" and
            pe.sections[1].name == "UPX1"
        )
}
```

### Step 4: Scan Files and Directories with yara-python

```python
import yara
import os
import json
from datetime import datetime
from pathlib import Path

def compile_rules(rule_paths):
    """Compile YARA rules from one or more .yar files."""
    rule_files = {}
    for i, path in enumerate(rule_paths):
        namespace = Path(path).stem
        rule_files[namespace] = path
    return yara.compile(filepaths=rule_files)

def scan_directory(rules, target_dir, recursive=True):
    """Scan a directory for matches and return structured results."""
    results = []
    scan_count = 0
    error_count = 0

    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            filepath = os.path.join(root, filename)
            scan_count += 1
            try:
                matches = rules.match(filepath, timeout=60)
                if matches:
                    for match in matches:
                        result = {
                            "file": filepath,
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": match.tags,
                            "meta": match.meta,
                            "strings": [],
                            "scan_time": datetime.utcnow().isoformat()
                        }
                        for offset, identifier, data in match.strings:
                            result["strings"].append({
                                "offset": hex(offset),
                                "identifier": identifier,
                                "data": data.hex() if isinstance(data, bytes) else data
                            })
                        results.append(result)
                        print(f"  MATCH: {match.rule} -> {filepath}")
            except yara.TimeoutError:
                error_count += 1
                print(f"  TIMEOUT scanning {filepath}")
            except yara.Error as e:
                error_count += 1

        if not recursive:
            break

    print(f"\nScan complete: {scan_count} files scanned, "
          f"{len(results)} matches, {error_count} errors")
    return results

# Compile and scan
rules = compile_rules([
    "rules/emotet_loader.yar",
    "rules/suspicious_packed.yar"
])

matches = scan_directory(rules, "/mnt/evidence/collected_samples/")

# Export results
with open("yara_scan_results.json", "w") as f:
    json.dump(matches, f, indent=2)
```

### Step 5: Scan Process Memory Dumps

Hunt for in-memory indicators that only exist in running processes:

```python
import yara

def scan_memory_dump(rules, dump_path):
    """Scan a process memory dump for YARA matches."""
    matches = rules.match(dump_path, timeout=120)

    for match in matches:
        print(f"Rule: {match.rule}")
        print(f"  Severity: {match.meta.get('severity', 'unknown')}")
        for offset, identifier, data in match.strings:
            # Show context around the match
            print(f"  String {identifier} at offset {hex(offset)}")
            if len(data) <= 64:
                print(f"    Data: {data.hex()}")

    return matches

# Rules targeting in-memory artifacts
memory_rules = yara.compile(source="""
rule Cobalt_Strike_Beacon_Memory {
    meta:
        description = "Detects Cobalt Strike beacon in process memory"
        severity = "critical"
    strings:
        $config_start = { 2E 2F 2E 2F 2E 2C }
        $sleep_mask = { 48 8B 44 24 ?? 48 89 44 24 ?? 48 8B 44 24 }
        $named_pipe = "\\\\\\\\.\\\\pipe\\\\msagent_" ascii
        $watermark = { 00 00 00 00 00 00 ?? ?? 00 00 }
    condition:
        2 of them
}
""")

scan_memory_dump(memory_rules, "/mnt/evidence/lsass_dump.dmp")
```

### Step 6: Generate Rules Automatically with yarGen

Use yarGen to create rules from malware samples by extracting unique strings:

```bash
# Clone and set up yarGen
git clone https://github.com/Neo23x0/yarGen.git
cd yarGen
pip install -r requirements.txt

# Download the string databases (run once)
python3 yarGen.py --update

# Generate rules from a directory of malware samples
python3 yarGen.py \
    -m /mnt/evidence/malware_samples/ \
    -o generated_rules.yar \
    --excludegood \
    -p "AutoGen" \
    -a "Threat Hunting Team" \
    --score 50

# Generate rules for a single sample with maximum detail
python3 yarGen.py \
    -m /mnt/evidence/malware_samples/suspicious.exe \
    -o single_sample_rule.yar \
    --opcodes \
    --debug
```

### Step 7: Integrate Community Rule Sets

Download and combine rules from public threat intelligence repositories:

```bash
# Clone Florian Roth's signature-base (large community rule set)
git clone https://github.com/Neo23x0/signature-base.git

# Clone YARA-Rules community repository
git clone https://github.com/Yara-Rules/rules.git yara-community-rules

# Clone ReversingLabs YARA rules
git clone https://github.com/reversinglabs/reversinglabs-yara-rules.git
```

```python
import yara
from pathlib import Path

def load_rule_directory(rule_dir, extensions=(".yar", ".yara")):
    """Load all YARA rules from a directory tree."""
    rule_files = {}
    for ext in extensions:
        for rule_file in Path(rule_dir).rglob(f"*{ext}"):
            namespace = rule_file.stem
            # Avoid namespace collisions
            if namespace in rule_files:
                namespace = f"{rule_file.parent.name}_{namespace}"
            rule_files[namespace] = str(rule_file)

    print(f"Loading {len(rule_files)} rule files from {rule_dir}")
    try:
        compiled = yara.compile(filepaths=rule_files)
        return compiled
    except yara.SyntaxError as e:
        print(f"Syntax error in rules: {e}")
        # Fall back to loading rules one by one, skipping broken ones
        valid_rules = {}
        for ns, path in rule_files.items():
            try:
                yara.compile(filepath=path)
                valid_rules[ns] = path
            except yara.SyntaxError:
                print(f"  Skipping broken rule: {path}")
        return yara.compile(filepaths=valid_rules)

# Load and scan with community rules
community_rules = load_rule_directory("signature-base/yara/")
matches = community_rules.match("/mnt/evidence/suspicious_file.exe", timeout=120)

for m in matches:
    print(f"Matched: {m.rule} (namespace: {m.namespace})")
```

### Step 8: Build a Continuous Hunting Pipeline

Automate scanning of new files as they arrive using filesystem monitoring:

```python
import yara
import time
import json
import hashlib
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class YaraHuntingHandler(FileSystemEventHandler):
    def __init__(self, rules, alert_file="yara_alerts.jsonl"):
        self.rules = rules
        self.alert_file = alert_file
        self.scanned_hashes = set()

    def on_created(self, event):
        if event.is_directory:
            return
        self._scan_file(event.src_path)

    def _scan_file(self, filepath):
        # Deduplicate by file hash
        try:
            file_hash = hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
        except (PermissionError, FileNotFoundError):
            return

        if file_hash in self.scanned_hashes:
            return
        self.scanned_hashes.add(file_hash)

        matches = self.rules.match(filepath, timeout=60)
        if matches:
            alert = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "file": filepath,
                "sha256": file_hash,
                "matches": [
                    {"rule": m.rule, "severity": m.meta.get("severity", "unknown")}
                    for m in matches
                ]
            }
            with open(self.alert_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
            print(f"ALERT: {filepath} matched {len(matches)} rules")

# Set up continuous monitoring
rules = yara.compile(filepaths={"hunting": "rules/all_hunting_rules.yar"})
handler = YaraHuntingHandler(rules)
observer = Observer()
observer.schedule(handler, path="/mnt/quarantine/", recursive=True)
observer.start()
print("YARA hunting pipeline active. Monitoring /mnt/quarantine/ ...")
```

## Verification

- Compile all custom rules without syntax errors: `yara -w rules/*.yar /dev/null`
- Confirm rules match known-good malware samples from your test corpus (true positive validation)
- Verify rules do NOT match a goodware corpus of common system files (false positive testing)
- Test scanning performance: single file scan should complete within timeout threshold
- Validate yarGen output rules compile and produce meaningful matches against the input samples
- Check that community rule sets load without critical syntax errors after filtering
- Confirm the continuous hunting pipeline generates alerts in JSONL format when test files are dropped
- Cross-reference YARA matches against VirusTotal or sandbox results to validate detection accuracy

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
