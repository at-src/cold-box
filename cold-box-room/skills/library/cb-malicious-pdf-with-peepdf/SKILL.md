---
name: cb-malicious-pdf-with-peepdf
skill_id: cb-malicious-pdf-with-peepdf
journal_id: CB-SKL-295
description: Cold-box analyst playbook — Malicious Pdf With Peepdf. Perform static
  analysis of malicious PDF documents using peepdf, pdfid, and pdf-parser to extract
  embedded JavaScript, shellcode, and suspicious objects.
domain: cold-box
subdomain: malware-analysis
tier: adjacent
case_profiles:
- malware_analysis
execution_mode: sift_runnable
artifact_platforms:
- any
host_platforms:
- linux
tags:
- malware-analysis
- pdf
- peepdf
- pdfid
- pdf-parser
- static-analysis
- reverse-engineering
- dfir
cold_box_version: 2
inspired_by: analyzing-malicious-pdf-with-peepdf
---

# Malicious Pdf With Peepdf (cold-box)

> **Journal ID:** `CB-SKL-295` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-295`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-malicious-pdf-with-peepdf")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-malicious-pdf-with-peepdf")` → note **`CB-SKL-295`**
2. `log_skill(case_id, journal_id="CB-SKL-295", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-295` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- When triaging suspicious PDF attachments from phishing emails
- During malware analysis of PDF-based exploit documents
- When extracting embedded JavaScript, shellcode, or executables from PDFs
- For forensic examination of weaponized document artifacts
- When building detection signatures for PDF-based threats

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `file` | `SIFT-008` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-295] file per playbook step",
  "why": "Executing cb-malicious-pdf-with-peepdf \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-295` (`cb-malicious-pdf-with-peepdf`)

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

- When triaging suspicious PDF attachments from phishing emails
- During malware analysis of PDF-based exploit documents
- When extracting embedded JavaScript, shellcode, or executables from PDFs
- For forensic examination of weaponized document artifacts
- When building detection signatures for PDF-based threats

## Prerequisites

- Python 3.8+ with peepdf-3 installed (pip install peepdf-3)
- pdfid.py and pdf-parser.py from Didier Stevens suite
- Isolated analysis environment (VM or sandbox)
- Optional: PyV8 for JavaScript emulation within peepdf
- Optional: Pylibemu for shellcode analysis

## Workflow

1. **Triage with pdfid**: Scan PDF for suspicious keywords (/JS, /JavaScript, /OpenAction, /Launch, /EmbeddedFile).
2. **Interactive Analysis**: Open PDF in peepdf interactive mode to explore object structure.
3. **Identify Suspicious Objects**: Locate objects containing JavaScript, streams, or encoded data.
4. **Extract Content**: Dump suspicious streams and decode filters (FlateDecode, ASCIIHexDecode).
5. **Deobfuscate JavaScript**: Analyze extracted JS for shellcode, heap sprays, or exploit code.
6. **Check VirusTotal**: Use peepdf vtcheck to cross-reference file hash with AV detections.
7. **Generate IOCs**: Extract URLs, domains, hashes, and shellcode signatures.

## Key Concepts

| Concept | Description |
|---------|-------------|
| /OpenAction | Automatic action executed when PDF is opened |
| /JavaScript /JS | Embedded JavaScript code in PDF objects |
| /Launch | Action that launches external applications |
| /EmbeddedFile | File embedded within the PDF structure |
| FlateDecode | zlib compression filter used to hide content |
| Object Streams | PDF objects stored in compressed streams |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| peepdf / peepdf-3 | Interactive PDF analysis with JS emulation |
| pdfid.py | Quick triage scanning for suspicious keywords |
| pdf-parser.py | Deep object-level PDF parsing |
| VirusTotal | Hash lookup and AV detection cross-reference |
| CyberChef | Decode and transform extracted payloads |

## Output Format

```
Analysis Report: PDF-MAL-[DATE]-[SEQ]
File: [filename.pdf]
SHA-256: [hash]
Suspicious Keywords: [/JS, /OpenAction, etc.]
Objects with JavaScript: [Object IDs]
Extracted URLs: [List]
Shellcode Detected: [Yes/No]
Embedded Files: [Count and types]
VirusTotal Detections: [X/Y engines]
Risk Level: [Critical/High/Medium/Low]
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
