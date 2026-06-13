# Tool catalog schema (`tools/manifest.json`)

One JSON file holds all SIFT operators (target: 234). The MCP server loads this catalog; the agent discovers tools via `list_sift_tools` / `describe_sift_tool`, then runs via `run_sift_tool(tool_id=…)`.

Machine validation: `tools/manifest.schema.json`.

## Top-level manifest

| Field | Type | Meaning |
|-------|------|---------|
| `schema` | string | `cold_box_room.tools_manifest_v1` |
| `host_os` | string | Host OS where catalog was verified |
| `count` | int | Must match `tools.length` |
| `tools` | array | Tool records |

## Each tool record

| Field | Meaning |
|-------|---------|
| **tool_id** | Stable id, e.g. `SIFT-148` — agent passes this to `run_sift_tool` |
| **name** | Short name (`fls`) |
| **binary** | Executable name on PATH |
| **category** | Filter group (`sleuthkit`, `common`, `zimmerman`, …) |
| **description** | What it does (agent-facing prose) |
| **host_platforms** | Where binary runs: `linux`, `darwin`, `windows` |
| **artifact_platforms** | Evidence it applies to: `any`, `windows`, … |
| **input.style** | `positional` \| `flag` \| `stdin` \| `none` |
| **input.flag** | Primary flag when `style=flag` |
| **input.common_flags** | Documented flags (flag, description, required) |
| **input.harness_usage** | How `extra_args` map to the real command |
| **output.format** | `text` \| `json` \| `csv` \| `binary` |
| **output.style** | `stdout` \| `stderr` \| `scratch_file` \| `inode_stream` |
| **timeout_seconds** | Harness kill timeout |
| **interactive** | Usually `false` |
| **verification.status** | `ok` \| `not_tested` \| `bad` \| `unavailable` |
| **verification.detail** | Human note (why not tested, not installed, etc.) |
| **verification.runnable** | Harness may run when true and status allows |

### Verification status (agent-facing)

| status | label (in describe) | Meaning |
|--------|---------------------|---------|
| `ok` | lab tested | Auto-verified on host |
| `not_tested` | not tested | Fine to use; not lab auto-tested |
| `unavailable` | not installed on host | Binary missing — cannot run |
| `bad` | do not use | Blocked by harness |

## Example

See `manifest.json` — batches 1–4: `SIFT-001` … `SIFT-200` (200 tools).

## Batches

| Batch | tool_id range | count |
|-------|---------------|------:|
| 1 | SIFT-001 … SIFT-050 | 50 |
| 2 | SIFT-051 … SIFT-100 | 50 |
| 3 | SIFT-101 … SIFT-150 | 50 |
| 4 | SIFT-151 … SIFT-200 | 50 |

## Adding batch 5+ (SIFT-201 …)

Append objects to `tools`, bump `count`, keep `tool_id` unique (`SIFT-###`).
