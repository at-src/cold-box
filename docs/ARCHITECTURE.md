# cold-box architecture

Autonomous postmortem investigator for dead Windows hosts (disk + memory).

## Components

```text
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Agent loop  │────▶│ MCP tools    │────▶│ Evidence (RO)   │
│ det / LLM   │     │ typed JSON   │     │ EVIDENCE_ROOT   │
└──────┬──────┘     └──────┬───────┘     └─────────────────┘
       │                   │
       │            ┌──────▼───────┐
       │            │ audit.jsonl  │  hash-chained append-only
       │            └──────┬───────┘
       │                   │
       ▼            ┌──────▼───────┐
┌─────────────┐     │ Finding gate │  audit_ids required
│ Verifier    │     └──────┬───────┘
│ R1–R6 Py    │            │
└──────┬──────┘     ┌──────▼───────┐
       │            │ report.md    │
       └───────────▶│ progress.jsonl
                    └──────────────┘
```

| Box | Role | LLM? |
|-----|------|------|
| `postmortem_evidence` | SHA-256 manifest, read-only guard | No |
| `postmortem_mcp` | 11 typed tools, ToolNotFound guardrails | No |
| `postmortem_audit` | Append-only audit log + chain verify | No |
| `postmortem_verify` | Deterministic rules R1–R6 | **No — the moat** |
| `postmortem_agent` | deterministic / synthetic / **llm** modes | Optional driver |
| `postmortem_report` | Finding gate + report generation | No |

## Constraint boundaries

| Control | Type | Where |
|---------|------|--------|
| No shell / write / mount tools | Architectural | `postmortem_mcp/dispatch.py` FORBIDDEN_TOOLS |
| Evidence path write block | Architectural | `postmortem_evidence/guard.py` |
| Finding without audit_id rejected | Architectural | `postmortem_report/gate.py` |
| Verifier contradictions | Deterministic Python | `postmortem_verify/rules.py` |
| LLM tool choice | Prompt + JSON schema | `postmortem_agent/live.py` |

Prompt-only guardrails are **not** the primary control — typed MCP + verifier veto are.

## Agent modes

| Mode | Driver | Use |
|------|--------|-----|
| `--synthetic` | Scripted fixtures | CI, fast R1 demo |
| `--profile lab` | Scripted multi-finding | Bundled cold-box-lab |
| `--mode llm` | Anthropic API | Live investigation |
| `--from-cache` | Cached Vol JSON | Fast Ali Hadi replay |

## Verifier rules

| Rule | Cross-source check |
|------|-------------------|
| R1 | psscan vs pslist hidden process |
| R2 | memory process without prefetch/amcache |
| R3 | Security logon without memory session |
| R4 | MFT timestomp ($SI vs $FN) |
| R5 | Prefetch binary missing on disk |
| R6 | netscan PID absent from pslist |
