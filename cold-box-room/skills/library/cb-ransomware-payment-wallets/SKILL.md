---
name: cb-ransomware-payment-wallets
skill_id: cb-ransomware-payment-wallets
journal_id: CB-SKL-317
description: Cold-box analyst playbook — Ransomware Payment Wallets. Traces ransomware
  cryptocurrency payment flows using blockchain analysis tools such as Chainalysis
  Reactor, WalletExplorer, and blockchain.com APIs. Identifies wallet clusters, tracks
  fund movement through mixers and exchanges, and supports
domain: cold-box
subdomain: ransomware-defense
tier: adjacent
case_profiles:
- threat_intel
execution_mode: reference
artifact_platforms:
- any
host_platforms:
- linux
tags:
- ransomware
- blockchain
- cryptocurrency
- forensics
- threat-intelligence
- bitcoin
cold_box_version: 2
inspired_by: analyzing-ransomware-payment-wallets
---

# Ransomware Payment Wallets (cold-box)

> **Journal ID:** `CB-SKL-317` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-317`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ransomware-payment-wallets")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ransomware-payment-wallets")` → note **`CB-SKL-317`**
2. `log_skill(case_id, journal_id="CB-SKL-317", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-317` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- An organization has been hit by ransomware and the ransom note contains a Bitcoin or cryptocurrency wallet address that needs investigation
- Law enforcement or incident responders need to trace where ransom payments flowed after the victim paid
- Threat intelligence analysts are attributing ransomware campaigns by clustering payment infrastructure across incidents
- Investigators need to determine if a ransomware group is reusing wallet infrastructure across multiple victims
- Compliance or legal teams need evidence of fund flows for prosecution, sanctions enforcement, or insurance claims

## Tool map (SIFT via MCP)

**Execution mode:** `reference` — procedure steps target external platforms (SIEM, cloud, etc.).
Use for investigation guidance; log `{journal_id}` and note gaps when SIFT cannot run a step.

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

_No SIFT tools mapped for this playbook on cold-box._
Follow the procedure for reasoning; document external-platform gaps in the journal.

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-317` (`cb-ransomware-payment-wallets`)

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

- An organization has been hit by ransomware and the ransom note contains a Bitcoin or cryptocurrency wallet address that needs investigation
- Law enforcement or incident responders need to trace where ransom payments flowed after the victim paid
- Threat intelligence analysts are attributing ransomware campaigns by clustering payment infrastructure across incidents
- Investigators need to determine if a ransomware group is reusing wallet infrastructure across multiple victims
- Compliance or legal teams need evidence of fund flows for prosecution, sanctions enforcement, or insurance claims

**Do not use** this skill for live payment interception or to interact directly with ransomware operators. All analysis should be passive and read-only against public blockchain data.

## Prerequisites

- Python 3.8+ with `requests`, `json`, and `hashlib` libraries
- Access to blockchain explorer APIs (blockchain.com, WalletExplorer.com, Blockstream.info)
- Familiarity with Bitcoin transaction model (UTXOs, inputs, outputs, change addresses)
- Understanding of common obfuscation techniques (mixers, tumblers, peel chains, cross-chain swaps)
- Optional: Chainalysis Reactor license for enterprise-grade cluster analysis
- Optional: OXT.me for advanced transaction graph visualization

## Workflow

### Step 1: Extract Wallet Address from Ransom Note

Parse the ransom note to identify the payment address(es):

```
Common address formats:
  Bitcoin (P2PKH):   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  (starts with 1)
  Bitcoin (P2SH):    3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy  (starts with 3)
  Bitcoin (Bech32):  bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq (starts with bc1)
  Monero:            4... (95 characters, much harder to trace)
  Ethereum:          0x... (40 hex chars)
```

### Step 2: Query Blockchain Explorer for Transaction History

Retrieve all transactions associated with the wallet:

```python
import requests

def get_wallet_transactions(address):
    """Query blockchain.com API for address transactions."""
    url = f"https://blockchain.info/rawaddr/{address}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "address": address,
        "n_tx": data.get("n_tx", 0),
        "total_received_satoshi": data.get("total_received", 0),
        "total_sent_satoshi": data.get("total_sent", 0),
        "final_balance_satoshi": data.get("final_balance", 0),
        "transactions": data.get("txs", []),
    }
```

### Step 3: Map Fund Flow and Identify Clusters

Trace outputs from the ransom wallet to downstream addresses:

```
Fund Flow Analysis:
━━━━━━━━━━━━━━━━━━
Victim Payment ──► Ransom Wallet ──► Consolidation Wallet
                                  ├─► Mixer/Tumbler Service
                                  ├─► Exchange Deposit Address
                                  └─► Peel Chain (sequential small outputs)

Key indicators:
  - Consolidation: Multiple ransom payments aggregated into one wallet
  - Peel chains: Sequential transactions with diminishing outputs
  - Mixer usage: Funds sent to known mixer addresses (Wasabi, Samourai, ChipMixer)
  - Exchange cashout: Deposits to known exchange wallets (Binance, Kraken hot wallets)
```

### Step 4: Cross-Reference with Known Wallet Databases

Check addresses against known ransomware infrastructure:

```python
# Check WalletExplorer for entity identification
def check_wallet_explorer(address):
    url = f"https://www.walletexplorer.com/api/1/address?address={address}&caller=research"
    resp = requests.get(url, timeout=30)
    data = resp.json()
    return {
        "wallet_id": data.get("wallet_id"),
        "label": data.get("label", "Unknown"),
        "is_exchange": data.get("is_exchange", False),
    }
```

### Step 5: Generate Attribution Report

Compile findings into a structured intelligence report:

```
RANSOMWARE WALLET ANALYSIS REPORT
====================================
Ransom Address:      bc1q...xyz
Family Attribution:  LockBit 3.0 (based on ransom note format)
Total Received:      4.25 BTC ($178,500 at time of payment)
Total Sent:          4.25 BTC (wallet fully drained)
Number of Payments:  3 (likely 3 separate victims)

FUND FLOW:
  Payment 1: 1.5 BTC → Consolidation wallet → Binance deposit
  Payment 2: 1.0 BTC → Wasabi Mixer → Unknown
  Payment 3: 1.75 BTC → Peel chain (12 hops) → OKX deposit

CLUSTER ANALYSIS:
  Related wallets: 47 addresses identified in same cluster
  Total cluster volume: 156.3 BTC ($6.5M USD)
  First activity: 2024-01-15
  Last activity: 2024-09-22
```

## Verification

- Confirm wallet address format is valid before querying APIs
- Cross-reference transaction timestamps with known incident timelines
- Validate cluster associations by checking common-input-ownership heuristic
- Compare findings against OFAC SDN list for sanctioned addresses
- Verify exchange attribution against multiple sources (WalletExplorer, OXT, Chainalysis)

## Key Concepts

| Term | Definition |
|------|------------|
| **UTXO** | Unspent Transaction Output; the fundamental unit of Bitcoin that tracks ownership through a chain of transactions |
| **Cluster Analysis** | Grouping multiple Bitcoin addresses believed to be controlled by the same entity using common-input-ownership and change-address heuristics |
| **Peel Chain** | A laundering pattern where funds are sent through many sequential transactions, each peeling off a small amount to a new address |
| **CoinJoin/Mixer** | Privacy techniques that combine multiple users' transactions to obscure the link between sender and receiver |
| **Common Input Ownership** | Heuristic that assumes all inputs to a single transaction are controlled by the same entity |

## Tools & Systems

- **Chainalysis Reactor**: Enterprise blockchain investigation platform with entity attribution and cross-chain tracing
- **WalletExplorer**: Free tool that clusters Bitcoin addresses and labels known services (exchanges, mixers, markets)
- **OXT.me**: Advanced Bitcoin transaction visualization with UTXO graph analysis
- **Blockstream.info**: Open-source Bitcoin block explorer with full API access
- **blockchain.com API**: Free API for querying Bitcoin address balances and transaction histories
- **OFAC SDN List**: U.S. Treasury sanctioned address list for compliance checking

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
