---
name: cb-yara-rule-development-for-detection
skill_id: cb-yara-rule-development-for-detection
journal_id: CB-SKL-124
description: Cold-box analyst playbook — Yara Rule Development For Detection. Develop
  precise YARA rules for malware detection by identifying unique byte patterns, strings,
  and behavioral indicators in executable files while minimizing false positives.
domain: cold-box
subdomain: malware-analysis
tier: core
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- yara
- malware-detection
- signature-development
- threat-hunting
- pattern-matching
- yara-x
- indicator-development
cold_box_version: 2
inspired_by: performing-yara-rule-development-for-detection
---

# Yara Rule Development For Detection (cold-box)

> **Journal ID:** `CB-SKL-124` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-124`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-yara-rule-development-for-detection")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-yara-rule-development-for-detection")` → note **`CB-SKL-124`**
2. `log_skill(case_id, journal_id="CB-SKL-124", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-124` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When conducting security assessments that involve performing yara rule development for detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `powershell` | `SIFT-179` | no | no |
| `strings` | `SIFT-044` | yes | yes |
| `find` | `SIFT-009` | yes | yes |
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
  "purpose": "[CB-SKL-124] powershell per playbook step",
  "why": "Executing cb-yara-rule-development-for-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `strings` → `SIFT-044`

```json
{
  "tool_id": "SIFT-044",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-124] strings per playbook step",
  "why": "Executing cb-yara-rule-development-for-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-124] find per playbook step",
  "why": "Executing cb-yara-rule-development-for-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-124] yara per playbook step",
  "why": "Executing cb-yara-rule-development-for-detection \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-124] file per playbook step",
  "why": "Executing cb-yara-rule-development-for-detection \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-124` (`cb-yara-rule-development-for-detection`)

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

YARA is the pattern matching swiss knife for malware researchers, enabling identification and classification of malware based on textual or binary patterns. Effective YARA rules combine unique string patterns, byte sequences, PE header characteristics, import table analysis, and conditional logic to detect malware families while avoiding false positives. Modern YARA-X (rewritten in Rust, stable since June 2025) brings improved performance and new modules. Rules should target unpacked malware artifacts like hardcoded stack strings, C2 URLs, mutex names, encryption constants, and unique code sequences rather than packer signatures.


## When to Use

- When conducting security assessments that involve performing yara rule development for detection
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Python 3.9+ with `yara-python` library
- YARA 4.5+ or YARA-X 0.10+
- PE analysis tools (`pefile`, `pestudio`)
- Hex editor for identifying unique byte patterns
- Access to malware samples (VirusTotal, MalwareBazaar)
- Understanding of PE file format, strings, and import tables

## Key Concepts

### Rule Structure

Every YARA rule consists of three sections: `meta` (optional descriptive metadata), `strings` (pattern definitions), and `condition` (matching logic). String types include text strings (ASCII/wide/nocase), hex patterns with wildcards and jumps, and regular expressions. Conditions combine string matches with file properties using boolean operators.

### String Selection Strategy

Effective rules target patterns that are unique to the malware family and survive recompilation. Hardcoded stack strings are excellent choices because compilers embed them consistently. C2 domain patterns, custom encryption routines, unique error messages, and specific API call sequences provide stable detection anchors. Avoid compiler-generated boilerplate and common library strings.

### Performance Optimization

YARA evaluates conditions short-circuit style. Place the most discriminating and cheapest-to-evaluate conditions first. Use `filesize` limits to skip irrelevant files quickly. Minimize regex usage in favor of hex patterns. Use `private` rules as building blocks for complex detection logic without generating standalone matches.

## Workflow

### Step 1: Analyze Sample for Unique Patterns

```python
#!/usr/bin/env python3
"""Extract candidate strings and byte patterns for YARA rule creation."""
import pefile
import re
import sys
from collections import Counter


def extract_strings(filepath, min_length=6):
    """Extract ASCII and wide strings from binary."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # ASCII strings
    ascii_strings = re.findall(
        rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}', data
    )

    # Wide (UTF-16LE) strings
    wide_strings = re.findall(
        rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}', data
    )

    return {
        'ascii': [s.decode('ascii') for s in ascii_strings],
        'wide': [s.decode('utf-16-le') for s in wide_strings],
    }


def analyze_pe_imports(filepath):
    """Extract import table for API-based detection."""
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        return []

    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace')
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                    imports.append(f"{dll_name}!{func_name}")
    return imports


def find_unique_byte_patterns(filepath, pattern_length=16):
    """Find unique byte sequences suitable for YARA hex patterns."""
    with open(filepath, 'rb') as f:
        data = f.read()

    try:
        pe = pefile.PE(filepath)
        # Focus on code section
        for section in pe.sections:
            if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                code_start = section.PointerToRawData
                code_end = code_start + section.SizeOfRawData
                code_data = data[code_start:code_end]
                break
        else:
            code_data = data
    except Exception:
        code_data = data

    # Find byte patterns that appear exactly once
    patterns = []
    for i in range(0, len(code_data) - pattern_length, 4):
        pattern = code_data[i:i+pattern_length]
        if pattern.count(b'\x00') < pattern_length // 3:  # Skip null-heavy
            hex_pattern = ' '.join(f'{b:02X}' for b in pattern)
            patterns.append(hex_pattern)

    # Count frequency and return unique ones
    freq = Counter(patterns)
    unique = [p for p, count in freq.items() if count == 1]

    return unique[:20]  # Top 20 candidates


def suggest_rule_strings(filepath):
    """Suggest strings and patterns for YARA rule."""
    print(f"[+] Analyzing: {filepath}")

    # Extract strings
    strings = extract_strings(filepath)

    # Filter for suspicious/unique strings
    suspicious_keywords = [
        'http', 'https', 'cmd', 'powershell', 'mutex', 'pipe',
        'password', 'credential', 'inject', 'hook', 'debug',
        'sandbox', 'virtual', 'vmware', 'vbox',
    ]

    print("\n[+] Suspicious ASCII strings:")
    for s in strings['ascii']:
        if any(kw in s.lower() for kw in suspicious_keywords):
            print(f"  $ = \"{s}\" ascii")

    print("\n[+] Suspicious wide strings:")
    for s in strings['wide']:
        if any(kw in s.lower() for kw in suspicious_keywords):
            print(f"  $ = \"{s}\" wide")

    # Import analysis
    imports = analyze_pe_imports(filepath)
    suspicious_apis = [
        'VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory',
        'CreateRemoteThread', 'NtUnmapViewOfSection', 'RtlMoveMemory',
        'OpenProcess', 'CreateToolhelp32Snapshot',
        'InternetOpenA', 'HttpSendRequestA',
        'CryptEncrypt', 'CryptDecrypt',
    ]

    print("\n[+] Suspicious imports:")
    for imp in imports:
        func = imp.split('!')[-1]
        if func in suspicious_apis:
            print(f"  {imp}")

    # Byte patterns
    print("\n[+] Candidate hex patterns:")
    patterns = find_unique_byte_patterns(filepath)
    for p in patterns[:5]:
        print(f"  $hex = {{ {p} }}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <sample_path>")
        sys.exit(1)
    suggest_rule_strings(sys.argv[1])
```

### Step 2: Write and Test YARA Rules

```python
import yara
import os

def create_yara_rule(rule_name, meta, strings, condition):
    """Generate a YARA rule from components."""
    meta_str = "\n".join(f'        {k} = "{v}"' for k, v in meta.items())
    strings_str = "\n".join(f"        {s}" for s in strings)

    rule = f"""rule {rule_name} {{
    meta:
{meta_str}

    strings:
{strings_str}

    condition:
        {condition}
}}"""
    return rule


def test_yara_rule(rule_text, test_dir):
    """Compile and test YARA rule against sample directory."""
    try:
        rules = yara.compile(source=rule_text)
    except yara.SyntaxError as e:
        print(f"[-] YARA syntax error: {e}")
        return None

    results = {"matches": [], "no_match": []}

    for filename in os.listdir(test_dir):
        filepath = os.path.join(test_dir, filename)
        if not os.path.isfile(filepath):
            continue

        matches = rules.match(filepath)
        if matches:
            results["matches"].append({
                "file": filename,
                "rules": [m.rule for m in matches],
            })
        else:
            results["no_match"].append(filename)

    print(f"[+] Matches: {len(results['matches'])}")
    print(f"[-] No match: {len(results['no_match'])}")
    return results


# Example: Create a rule for a hypothetical malware family
example_rule = create_yara_rule(
    rule_name="MalwareFamily_Variant_A",
    meta={
        "description": "Detects MalwareFamily Variant A",
        "author": "Malware Analysis Team",
        "date": "2025-01-01",
        "hash": "abc123...",
        "tlp": "WHITE",
    },
    strings=[
        '$mutex = "Global\\\\UniqueM4lwareMutex" ascii wide',
        '$c2_pattern = /https?:\\/\\/[a-z]{5,10}\\.(xyz|top|buzz)\\/gate\\.php/',
        '$api1 = "VirtualAllocEx" ascii',
        '$api2 = "WriteProcessMemory" ascii',
        '$api3 = "CreateRemoteThread" ascii',
        '$hex_decrypt = { 8B 45 ?? 33 C1 89 45 ?? 83 C1 04 }',
        '$pdb = "C:\\\\Users\\\\" ascii',
    ],
    condition=(
        'uint16(0) == 0x5A4D and filesize < 2MB and '
        '($mutex or $c2_pattern) and '
        '2 of ($api*) and '
        '$hex_decrypt'
    ),
)

print(example_rule)
```

### Step 3: Performance Testing and Optimization

```python
import time

def benchmark_rule(rule_text, scan_directory, iterations=3):
    """Benchmark YARA rule scan performance."""
    rules = yara.compile(source=rule_text)

    files = []
    for root, _, filenames in os.walk(scan_directory):
        for f in filenames:
            files.append(os.path.join(root, f))

    print(f"[+] Benchmarking against {len(files)} files "
          f"({iterations} iterations)")

    times = []
    for i in range(iterations):
        start = time.perf_counter()
        matches = 0
        for filepath in files:
            try:
                result = rules.match(filepath)
                if result:
                    matches += 1
            except Exception:
                pass
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        print(f"  Iteration {i+1}: {elapsed:.3f}s ({matches} matches)")

    avg_time = sum(times) / len(times)
    files_per_sec = len(files) / avg_time
    print(f"\n[+] Average: {avg_time:.3f}s ({files_per_sec:.0f} files/sec)")
    return avg_time
```

## Validation Criteria

- YARA rules compile without syntax errors
- Rules detect target malware family samples with zero false negatives
- False positive rate below 0.1% when scanned against clean file corpus
- Rule performance allows scanning 1000+ files per second
- Rules survive minor malware modifications (recompilation, string changes)
- Metadata includes hash, author, date, description, and TLP marking

## References

- [YARA Official Documentation](https://virustotal.github.io/yara/)
- [YARA-X Rewrite in Rust](https://github.com/VirusTotal/yara-x)
- [Yara-Rules Community Repository](https://github.com/Yara-Rules/rules)
- [ReversingLabs - Writing Detailed YARA Rules](https://www.reversinglabs.com/blog/writing-detailed-yara-rules-for-malware-detection)
- [YARA Rule Crafting Deep Dive](https://cyberthreatintelligencenetwork.com/index.php/2024/09/11/yara-rule-crafting-a-deep-dive-into-signature-based-threat-hunting-strategies/)

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
