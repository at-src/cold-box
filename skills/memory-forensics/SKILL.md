# Memory analysis

Run this when the case includes a Windows RAM capture and you need process, network, or injection evidence from volatile state.

## Setup

- Point `EVIDENCE_ROOT` at the read-only case tree.
- Send all writes to `CASE_OUTPUT/<case-id>/`.
- Set `VOL3` if `bin/vol` is not on PATH.
- Valid image extensions: `.mem`, `.raw`, `.dmp`, `.img`.

Every memory call returns JSON plus an `audit_id`. Attach that ID to any claim you promote to a finding.

## Tools you have

| Tool | What it gives you |
|------|-------------------|
| `mem_pslist` | Processes the kernel still links in the active list |
| `mem_psscan` | Processes found by pool scan — catches unlinked and some exited entries |
| `mem_cmdline` | Command lines keyed by PID |
| `mem_netscan` | Sockets and the PID that owned them at capture time |
| `mem_malfind` | Memory regions that look injected (RWX, PE headers in odd places) |

## How to work the case

**Start with integrity.** Hash the case (`evidence_manifest`) before you touch the dump.

**Compare two process views.** Call `mem_pslist`, then `mem_psscan` on the same file. Feed both into the verifier (R1). A hit means something showed up in the scan that pslist does not explain — hidden PID, or same PID with a different image name.

Important: on real images, pslist and psscan report different memory offsets for the same PID. That is normal. R1 only cares about PID and name, not offset.

**When R1 fires.** Pull `mem_cmdline` for the suspicious PID(s). If injection is still plausible, run `mem_malfind`. Drop confidence until the story matches the data or label the item unresolved and cite both audit IDs (pslist + psscan at minimum).

**Network check.** Run `mem_netscan` and compare connection PIDs to pslist. R6 flags sockets whose owner PID is not in the process list.

## Fast path vs live path

CI and the 30-second demo use JSON fixtures under `examples/sample-verifier/` (`r1-*`, `r6-*`). That avoids running Vol on a fake dump.

For Ali Hadi or NIST images, pass `--memory` relative to `EVIDENCE_ROOT` and expect minutes per plugin on large captures.

## Hard rules

- Only registered MCP tools exist. Shell helpers like `execute_shell` are not on the wire.
- A finding without at least one real `audit_id` will not pass report validation.
