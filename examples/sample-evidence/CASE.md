# Case cold-box-lab-01

**Type:** Synthetic lab (bundled)  
**Platform:** Windows 10 workstation  
**Narrative:** Post-phish staging — loader prefetch, timestomped dropper, hidden process in memory fixtures.

## Expected verifier signals (fixtures + disk)

| Rule | Signal in this case |
|------|---------------------|
| R1 | `evil.exe` in psscan, absent from pslist (`sample-verifier/`) |
| R2 | `ghostrunner.exe` in memory, no prefetch/amcache trail (fixtures) |
| R4 | `stage-dropper.exe` MFT $SI vs $FN mismatch (`disk/$MFT.csv`) |
| R5 | `STAGE-RUNNER.EXE` in prefetch, no binary on disk |
| R6 | PID 31337 in netscan, absent from pslist (fixtures) |

## MCP tools to run

1. `evidence_manifest`
2. `disk_parse_prefetch` → `disk/Windows/Prefetch/COLDLOADER.EXE-B1C2D3E4.pf`
3. `disk_detect_timestomp` → `disk/$MFT.csv`
4. Memory: `mem_pslist`, `mem_psscan`, `mem_netscan` against `/evidence` images in production

Every finding must cite `audit_id` from tool output.
