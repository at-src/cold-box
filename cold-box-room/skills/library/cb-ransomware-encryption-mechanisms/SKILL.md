---
name: cb-ransomware-encryption-mechanisms
skill_id: cb-ransomware-encryption-mechanisms
journal_id: CB-SKL-314
description: Cold-box analyst playbook — Ransomware Encryption Mechanisms. Analyzes
  encryption algorithms, key management, and file encryption routines used by ransomware
  families to assess decryption feasibility, identify implementation weaknesses, and
  support recovery efforts. Covers AES, RSA, ChaCha20, and hybr
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
- malware
- ransomware
- encryption
- cryptanalysis
- reverse-engineering
cold_box_version: 2
inspired_by: analyzing-ransomware-encryption-mechanisms
---

# Ransomware Encryption Mechanisms (cold-box)

> **Journal ID:** `CB-SKL-314` — cite this in every journal entry while following this playbook.

## Cold-box constraints (always)

- Evidence lives on the **sealed operation table** — read only through the viewport (`input_relpath`).
- **Never write** on `operation-table/`; tool output goes to `records/{case_id}/scratch/`.
- **Log this playbook** in the case journal with **`CB-SKL-314`** (`log_skill`) when you adopt it and at each major step.
- Every SIFT execution: `run_sift_tool` with **`purpose`**, **`why`**, and cite returned **`tool_id`** + **`audit_id`** in the journal.
- Prefer `list_sift_tools(verified_only=true)` — skip `[BAD — DO NOT USE]` tools.
- Load this playbook with `get_skill("cb-ransomware-encryption-mechanisms")`; do not treat markdown code blocks as direct shell commands.

## Agent loop

1. `suggest_skills(case_profile=...)` or `get_skill("cb-ransomware-encryption-mechanisms")` → note **`CB-SKL-314`**
2. `log_skill(case_id, journal_id="CB-SKL-314", action="adopted", note="...")`
3. `list_sift_tools(verified_only=true)` → pick tools from the map below
4. `describe_sift_tool(tool_id)` → `run_sift_tool(...)` → journal stdout with `CB-SKL-314` + `audit_id`
5. `log_skill(..., action="finding", note="...")` when recording conclusions; self-correct if outputs conflict


## When to use

- A ransomware infection has occurred and recovery requires understanding the encryption scheme used
- Assessing whether decryption is possible without paying the ransom (implementation flaws, known decryptors)
- Reverse engineering ransomware to identify the encryption algorithm, key derivation, and key storage mechanism
- Developing a decryptor tool when a weakness in the ransomware's cryptographic implementation is identified
- Classifying a ransomware sample by its encryption approach to attribute it to a known family

## Tool map (SIFT via MCP)

**Execution mode:** `sift_runnable` — SIFT tools below are available on this host.

| binary | tool_id | verified | available |
|--------|---------|----------|-----------|
| `handle` | `SIFT-178` | no | no |
| `find` | `SIFT-009` | yes | yes |
| `yara` | `SIFT-045` | no | no |
| `file` | `SIFT-008` | yes | yes |
| `zip` | `SIFT-036` | yes | yes |
| `7z` | `SIFT-046` | yes | yes |

## Cold-box MCP examples

Use these instead of running shell blocks directly. Always log `{journal_id}` in purpose/why or via `log_skill`.

### `handle` → `SIFT-178`

```json
{
  "tool_id": "SIFT-178",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] handle per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

### `find` → `SIFT-009`

```json
{
  "tool_id": "SIFT-009",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] find per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

### `yara` → `SIFT-045`

```json
{
  "tool_id": "SIFT-045",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] yara per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

### `file` → `SIFT-008`

```json
{
  "tool_id": "SIFT-008",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] file per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

### `zip` → `SIFT-036`

```json
{
  "tool_id": "SIFT-036",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] zip per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

### `7z` → `SIFT-046`

```json
{
  "tool_id": "SIFT-046",
  "case_id": "{case_id}",
  "input_relpath": "{artifact_relpath}",
  "purpose": "[CB-SKL-314] 7z per playbook step",
  "why": "Executing cb-ransomware-encryption-mechanisms \u2014 see Procedure section",
  "extra_args": []
}
```

## Journal logging

When you adopt this playbook, append to `records/{case_id}/{case_id}.md`:

```markdown
## {timestamp} — skill `CB-SKL-314` (`cb-ransomware-encryption-mechanisms`)

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

- A ransomware infection has occurred and recovery requires understanding the encryption scheme used
- Assessing whether decryption is possible without paying the ransom (implementation flaws, known decryptors)
- Reverse engineering ransomware to identify the encryption algorithm, key derivation, and key storage mechanism
- Developing a decryptor tool when a weakness in the ransomware's cryptographic implementation is identified
- Classifying a ransomware sample by its encryption approach to attribute it to a known family

**Do not use** for production data recovery operations without first verifying the decryption method on test copies of encrypted files.

## Prerequisites

- Ghidra or IDA Pro for reverse engineering the ransomware binary
- Python 3.8+ with `pycryptodome` library for testing encryption/decryption routines
- Sample encrypted files and their corresponding plaintext originals (known-plaintext pairs)
- Access to the ransomware binary (unpacked if applicable)
- Familiarity with symmetric (AES, ChaCha20) and asymmetric (RSA) cryptographic algorithms
- NoMoreRansom.org database for checking existing free decryptors

## Workflow

### Step 1: Identify the Encryption Algorithm

Determine which cryptographic algorithm the ransomware uses:

```python
# Check for Windows Crypto API usage in imports
import pefile

pe = pefile.PE("ransomware.exe")

crypto_apis = {
    "CryptAcquireContextA": "Windows CryptoAPI",
    "CryptAcquireContextW": "Windows CryptoAPI",
    "CryptGenKey": "Windows CryptoAPI key generation",
    "CryptEncrypt": "Windows CryptoAPI encryption",
    "CryptImportKey": "Windows CryptoAPI key import",
    "BCryptOpenAlgorithmProvider": "Windows CNG (modern crypto)",
    "BCryptEncrypt": "Windows CNG encryption",
    "BCryptGenerateKeyPair": "Windows CNG asymmetric key gen",
}

print("Crypto API Imports:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name and imp.name.decode() in crypto_apis:
            print(f"  {entry.dll.decode()} -> {imp.name.decode()}: {crypto_apis[imp.name.decode()]}")
```

```
Common Ransomware Encryption Schemes:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AES-256-CBC + RSA-2048:    Most common hybrid scheme (LockBit, REvil, Conti)
AES-256-CTR + RSA-4096:    Stream cipher mode variant (BlackCat/ALPHV)
ChaCha20 + RSA-4096:       Modern stream cipher (Hive, Royal)
Salsa20 + ECDH:            Curve25519 key exchange (Babuk)
AES-128-ECB:               Weak mode - potential decryption via known-plaintext
XOR-only:                  Trivial encryption - always recoverable
Custom algorithm:          Often contains implementation flaws
```

### Step 2: Analyze Key Generation and Management

Reverse engineer how encryption keys are generated and stored:

```
Key Management Patterns in Ransomware:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. STRONG (no recovery possible without key):
   - Per-file AES key generated with CryptGenRandom
   - AES key encrypted with embedded RSA public key
   - Encrypted key appended to each file or stored separately
   - RSA private key held only by attacker's C2 server

2. WEAK (potential recovery):
   - AES key derived from predictable seed (timestamp, PID)
   - Same AES key used for all files (single key compromise = full recovery)
   - Key transmitted to C2 before encryption starts (PCAP may contain key)
   - XOR with short repeating key (brute-forceable)
   - PRNG seeded with GetTickCount or time() (limited keyspace)

3. FLAWED IMPLEMENTATION:
   - ECB mode (preserves plaintext patterns)
   - Initialization vector (IV) reuse across files
   - Key stored in plaintext in memory (recoverable from memory dump)
   - Partial encryption (only first N bytes encrypted)
```

### Step 3: Examine File Encryption Routine

Reverse engineer the file processing logic:

```c
// Typical ransomware file encryption flow (decompiled pseudo-code from Ghidra):

void encrypt_file(char *filepath) {
    // 1. Check file extension against target list
    if (!is_target_extension(filepath)) return;

    // 2. Generate per-file AES key (32 bytes for AES-256)
    BYTE aes_key[32];
    CryptGenRandom(hProv, 32, aes_key);

    // 3. Generate random IV (16 bytes)
    BYTE iv[16];
    CryptGenRandom(hProv, 16, iv);

    // 4. Read file contents
    HANDLE hFile = CreateFile(filepath, GENERIC_READ, ...);
    BYTE *plaintext = read_entire_file(hFile);

    // 5. Encrypt with AES-256-CBC
    aes_cbc_encrypt(plaintext, file_size, aes_key, iv);

    // 6. Encrypt AES key with RSA public key
    BYTE encrypted_key[256];  // RSA-2048 output
    rsa_encrypt(aes_key, 32, rsa_pubkey, encrypted_key);

    // 7. Write: encrypted_data + encrypted_key + IV to file
    write_file(filepath, encrypted_data, encrypted_key, iv);

    // 8. Rename file with ransomware extension
    rename_file(filepath, strcat(filepath, ".locked"));
}
```

### Step 4: Check for Cryptographic Weaknesses

Test the implementation for exploitable flaws:

```python
from Crypto.Cipher import AES
import os
import struct

# Test 1: Check if same key is used for multiple files
# Compare encrypted versions of known files
def check_key_reuse(file1_enc, file2_enc):
    with open(file1_enc, "rb") as f:
        data1 = f.read()
    with open(file2_enc, "rb") as f:
        data2 = f.read()

    # Extract IVs (location depends on ransomware family)
    # If IVs are same and files share encrypted blocks -> same key
    iv1 = data1[-16:]  # Example: IV at end
    iv2 = data2[-16:]
    if iv1 == iv2:
        print("[!] Same IV detected - key reuse likely")

# Test 2: Check for predictable key derivation
# If key is derived from timestamp, iterate possible values
def brute_force_timestamp_key(encrypted_file, known_header, timestamp_range):
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()

    for ts in timestamp_range:
        # Derive key the same way ransomware does
        import hashlib
        key = hashlib.sha256(str(ts).encode()).digest()
        iv = encrypted_data[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data[:16])

        if decrypted[:len(known_header)] == known_header:
            print(f"[!] Key found! Timestamp: {ts}")
            return key

    return None

# Test 3: Check for ECB mode (pattern preservation)
def check_ecb_mode(encrypted_file):
    with open(encrypted_file, "rb") as f:
        data = f.read()
    # ECB produces identical ciphertext for identical plaintext blocks
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    unique = len(set(blocks))
    total = len(blocks)
    if unique < total * 0.95:
        print(f"[!] ECB mode likely: {total-unique} duplicate blocks out of {total}")
```

### Step 5: Attempt Key Recovery

Use identified weaknesses for key recovery:

```python
# Recovery Method 1: Extract key from memory dump
# Volatility plugin to scan for AES key schedules
# vol3 -f memory.dmp windows.yarascan --yara-rule "aes_key_schedule"

# Recovery Method 2: Known-plaintext attack (weak algorithms)
def xor_key_recovery(encrypted_file, known_plaintext):
    """Recover XOR key from known plaintext-ciphertext pair"""
    with open(encrypted_file, "rb") as f:
        ciphertext = f.read()

    key = bytes(c ^ p for c, p in zip(ciphertext, known_plaintext))
    # Find repeating key length
    for key_len in range(1, 256):
        candidate = key[:key_len]
        if all(key[i] == candidate[i % key_len] for i in range(min(len(key), key_len * 4))):
            print(f"XOR key (length {key_len}): {candidate.hex()}")
            return candidate
    return None

# Recovery Method 3: Check NoMoreRansom for existing decryptors
# https://www.nomoreransom.org/en/decryption-tools.html
```

### Step 6: Document Encryption Analysis

Compile findings into a structured report:

```
Analysis should document:
- Algorithm identified (AES, RSA, ChaCha20, custom)
- Key size and mode of operation (CBC, CTR, ECB, GCM)
- Key generation method (CSPRNG, predictable seed, static key)
- Key storage location (appended to file, registry, C2 transmission)
- File modification pattern (full encryption, partial, header-only)
- Targeted file extensions
- Ransom note format and payment infrastructure
- Decryption feasibility assessment (possible/impossible/partial)
- Recommended recovery approach
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Hybrid Encryption** | Combining symmetric (AES) for fast file encryption with asymmetric (RSA) for secure key wrapping; the standard ransomware approach |
| **Key Wrapping** | Encrypting the per-file symmetric key with the attacker's RSA public key so only the attacker's private key can decrypt it |
| **ECB Mode** | Electronic Codebook mode encrypts each block independently; preserves patterns in plaintext, a critical weakness enabling partial recovery |
| **Known-Plaintext Attack** | Using a known original file and its encrypted version to derive the encryption key; effective against XOR and weak stream ciphers |
| **Key Schedule** | The expanded form of an AES key in memory; scannable in memory dumps to recover encryption keys before they are erased |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator; ransomware using CryptGenRandom produces unpredictable keys |
| **Partial Encryption** | Some ransomware only encrypts the first N bytes or every Nth block for speed; unencrypted portions may aid recovery |

## Tools & Systems

- **Ghidra**: Reverse engineering suite for analyzing ransomware encryption routines at the assembly level
- **PyCryptodome**: Python cryptographic library for implementing and testing decryption routines
- **NoMoreRansom.org**: Free decryption tool repository maintained by Europol and security vendors for known ransomware families
- **Volatility**: Memory forensics framework for extracting encryption keys from RAM dumps of infected systems
- **CryptoTester**: Tool for identifying cryptographic algorithms based on constants and code patterns

## Common Scenarios

### Scenario: Assessing Decryption Feasibility for a Ransomware Incident

**Context**: An organization is hit with ransomware encrypting file servers. Management needs to know if decryption is possible without paying the ransom before making a recovery decision.

**Approach**:
1. Identify the ransomware family from ransom note, file extension, and sample hash (check ID Ransomware)
2. Check NoMoreRansom.org for existing free decryptors for this family
3. Reverse engineer the encryption routine in Ghidra to identify the algorithm and key management
4. Test for implementation weaknesses (key reuse, predictable seeds, ECB mode)
5. Check if PCAP from the incident captured the key transmission to C2 (if key was sent before encryption)
6. Scan memory dumps from affected machines for AES key schedules in RAM
7. Report findings: decryption possible/impossible with specific technical justification

**Pitfalls**:
- Testing decryption methods on the only copy of encrypted files (always work on copies)
- Assuming all files use the same key without verifying (some ransomware uses per-file keys)
- Not checking for volume shadow copies (vssadmin) which ransomware may have failed to delete
- Confusing the file encryption algorithm with the key wrapping algorithm in reports

## Output Format

```
RANSOMWARE ENCRYPTION ANALYSIS
================================
Sample:           lockbit3.exe
Family:           LockBit 3.0 / LockBit Black
SHA-256:          abc123def456...

ENCRYPTION SCHEME
File Cipher:      AES-256-CTR (per-file unique key)
Key Wrapping:     RSA-2048 (public key embedded in binary)
Key Generation:   CryptGenRandom (CSPRNG - unpredictable)
IV Generation:    Random 16 bytes per file
File Structure:   [encrypted_data][rsa_encrypted_key(256B)][iv(16B)][magic(8B)]

TARGETED EXTENSIONS
Total:            412 extensions targeted
Categories:       Documents (.doc, .xls, .pdf), Databases (.sql, .mdb),
                  Archives (.zip, .7z), Source code (.py, .java, .cs)
Excluded:         .exe, .dll, .sys, .lnk (system files preserved)

IMPLEMENTATION ANALYSIS
Key Strength:     STRONG - per-file random keys, no reuse
Mode Security:    STRONG - CTR mode with unique nonces
Key Storage:      RSA-encrypted key appended to each file
Shadow Copies:    Deleted via vssadmin and WMI

DECRYPTION FEASIBILITY
Without Key:      NOT POSSIBLE
  - No implementation flaws identified
  - RSA-2048 key wrapping prevents brute force
  - CSPRNG prevents key prediction
  - No existing free decryptor available

RECOVERY OPTIONS
1. Restore from offline backups (recommended)
2. Check for volume shadow copies (low probability - ransomware deletes them)
3. Memory forensics if machine was not rebooted (key may persist in RAM)
4. Negotiate with attacker (last resort - no guarantee of decryption)
```

## Self-correction

- If a SIFT tool errors, read `describe_sift_tool` and pick an alternate from the tool map.
- If procedure steps require SIEM/cloud/live APIs, log `{journal_id}` + `action=deferred` with the gap.
- Do not override `[BAD — DO NOT USE]` tools.
- Mark inference vs confirmed in journal; tie confirmed findings to `audit_id`.

## Limits

- Playbooks guide reasoning; **confirmed findings require tool output** in scratch with matching `audit_id`.
- Reference-mode steps are not executable on cold-box until equivalent SIFT tooling exists.
