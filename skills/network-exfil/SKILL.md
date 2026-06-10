---
name: Network exfil hunt
when_to_use: Case includes PCAP or DNS/HTTP logs and you need C2, beaconing, or DNS tunneling evidence
---

# Network exfil hunt

Run when `evidence_survey` reports `pcap` or network capture files.

## Tools

| Tool | Use |
|------|-----|
| `net_pcap_summary` | Protocol mix and size — first look |
| `net_dns_extract` | High-volume or long-label DNS (R8) |
| `net_http_extract` | Periodic same-size POSTs (R9) |
| `net_conversations` | Top talkers and lateral flows |

## Workflow

Start with `net_pcap_summary`, then branch on traffic shape: many DNS queries → `net_dns_extract`; HTTP-heavy → `net_http_extract`. Feed verifier R8/R9 before concluding exfil.
