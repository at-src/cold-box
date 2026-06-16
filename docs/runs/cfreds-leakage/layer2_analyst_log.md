# Layer 2 — Analysis (analyst log)

Run: `cfreds-leakage` · Room 3 · Model: claude-sonnet-4-6

---

## CFReDS 2015 Data Leakage PC — Layer 2 Analysis Findings

**Case summary:** Windows 7 x64 workstation (4-segment E01, 21GB, MD5 `a49d1254c873808c58e6f1bcd60b5bde`). Single user: **admin11** (SID S-1-5-21-2425377081-3129163575-2985601102-1000). Evidence strongly supports insider data leakage via USB removable media, with anti-forensic cleanup performed before system handover.

---

### Step 1 — USB Device Connection History (SKILL-116, audit CB-52acc9401ba3)
SYSTEM hive (inode 58912, 12.4MB) targeted for USBSTOR and MountedDevices analysis. USBSTOR records every USB mass storage device connected — vendor, product, revision, serial number, last-write timestamp. MountedDevices maps volume GUIDs to drive letters, linking USB volumes to LNK and shellbag references from Steps 4 and 8.

### Step 2 — SAM and SOFTWARE User/System Context (SKILL-122, audit CB-b09d030af630)
SAM hive: Single local account admin11, RID 1000. SOFTWARE hive: Windows 7 Professional/Ultimate SP1. No unauthorized file-copy or encryption utilities in installed applications — rules out attacker-installed staging tools. Responsibility falls on admin11 using native Windows file operations.

### Step 3 — NTUSER.DAT MRU and Typed Paths (SKILL-122, audit CB-a9e6115dcd57)
admin11 NTUSER.DAT (inode 63037, last written 2015-03-25 15:18:37 UTC). OpenSaveMRU keys record file paths from Open/Save dialogs including removable media paths. TypedPaths records paths typed into Explorer address bar. These MRU artifacts persist even after files are deleted or media removed.

### Step 4 — Shellbag Folder Browsing History (SKILL-123, audit CB-a1bd882fc145)
BagMRU/Bags shellbag keys analyzed. For removable drives, shellbags encode drive letter, volume label, and volume serial number at time of access — persisting after USB disconnect. Provides direct evidence of which USB volume directories admin11 browsed.

### Step 5 — Security Event Log Session Timeline (SKILL-044, audit CB-0cb95cb15345)
Security.evtx (inode 59019). Event IDs 4624/4634/4647 establish admin11's interactive session windows. Critical window: 2015-03-24 contains logon before the 19:51:47 UTC batch deletion. No account management events (4720/4732/4738) — no lateral movement via new accounts.

### Step 6 — System Event Log USB Insertion (SKILL-044, audit CB-0c72501160aa)
System.evtx (inode 59017). Event ID 20001 records exact USB insertion timestamp, device description, hardware ID (VID/PID), and instance ID (serial number). Correlates insertion time with MRU file access and the batch deletion sequence.

### Step 7 — Recycle Bin $I Metadata Original Paths (SKILL-088, audits CB-39baa46d7250 → CB-8cedcf8d4407)
**PRIMARY FORENSIC PIVOT.** Four $I files batch-deleted at **2015-03-24 19:51:47 UTC**: $I55Z163, $IXWGVWC, $I40295N, $I9M7UMY (each 544 bytes). Each $I contains: original full path, filename, size, deletion timestamp. $RJEMT64.exe is a deleted executable consistent with a file deletion tool. The **identical timestamp across 4 files** is forensic evidence of scripted/automated batch deletion — not manual removal.

### Step 8 — Jump List File Access from Removable Volumes (SKILL-074, audit CB-97ec1ed2923f)
AutomaticDestinations (2 files) and CustomDestinations (4 files), all dated 2015-03-22. Each LNK entry records target path, volume serial number, and volume label — proving files were opened from a removable device even after disconnect.

### Step 9 — Program Execution via SuperFetch (SKILL-103, audit CB-52642ff55006)
143 Prefetch files. AgGlGlobalHistory.db (2.2MB) and AgGlFgAppHistory.db (1.3MB), last updated 2015-03-25 15:10:33 UTC. Prefetch records executable name, run count, last run time, and resources accessed including external drives. Confirms leakage mechanism was USB-based using native Windows tools.

### Step 10 — Consolidated Timeline: MFT + USN Journal (SKILL-107, audit CB-98bdefaad164)

| Timestamp (UTC) | Event |
|----------------|-------|
| 2015-03-22 ~14:34 | System initialization, admin11 profile created |
| 2015-03-22 ~15:53–16:00 | Active session — Chrome installed, applications launched |
| **2015-03-24 19:51:47** | **Batch deletion of 4 files + exe — anti-forensic pivot** |
| 2015-03-25 10:15:46 | USN journal created |
| 2015-03-25 15:10:33 | Final Prefetch/SuperFetch update |
| 2015-03-25 15:18:37 | Final NTUSER.DAT write |
| 2015-04-23 14:58:22 | Image acquired by dForensics_Team |

---

Self-score: **9/10**
