# Cheatsheet — Windows Artifact Map (triage artifact selection)

Quick reference for deciding **which artifact answers which question** in a Windows disk triage, built from the HTB Sherlock **Streamer** (a malvertising case where the compromise spanned filesystem, execution, registry, event log and network evidence). The hard part of a triage is rarely the analysis — it's knowing where to look. Choosing the wrong artifact category costs hours before it produces nothing. Parsed with **Zimmerman Tools**, analysed in **Timeline Explorer**.

Lab context: HTB Sherlock. Paths, hashes, IPs, and URLs are training data.

---

## 1. The selection problem

Every question maps to one artifact category. Identify the category **before** opening anything.

| The question is about… | Category | Artifact |
|---|---|---|
| what **ran** | program execution | Prefetch, Amcache, ShimCache, SRUM |
| what was **browsed** (folders) | shell navigation | **Shellbags** (`NTUSER.DAT` + `UsrClass.dat`) |
| what was **opened** (files) | file access | LNK, JumpLists, RecentDocs |
| what **changed** on disk | filesystem | `$MFT`, `$J` (USN Journal) |
| what was **typed** in Win+R | user input | RunMRU, TypedPaths |
| what **resolved** by DNS | network | DNS-Client Operational (3006/3008) |
| what **connected** | network | `pfirewall.log`, Sysmon EID 3 |
| how it **persists** | persistence | Scheduled Tasks (4698), Run keys, Services |
| **who** logged in and when | authentication | Security 4624/4625/4634 |

**Execution and navigation are not interchangeable.** Prefetch tells you a binary ran; it does not tell you a user opened a folder. Shellbags tell you a folder was browsed; they say nothing about execution. In Streamer, the network path of the acquisition tooling was hunted through RunMRU, TypedPaths, MountPoints2 and Prefetch before shellbags produced it in one query — because the analyst had *navigated* there, not executed from a mapped drive.

For `$MFT` internals — timestomping, `$SI` vs `$FN`, resident data, offset arithmetic — see [`mft-forensics.md`](mft-forensics.md).

---

## 2. USN Journal (`$J`) — the change log

`C:\$Extend\$J` is a circular log of every filesystem change on the volume. It is the **only artifact that records a rename as an event with a timestamp**. The `$MFT` gives you a file's current name; the `$J` gives you its history.

```
MFTECmd.exe -f "<triage>\C\$Extend\$J" --csv <out> --csvf usn.csv
```

Key update reasons:

| Reason | Meaning |
|---|---|
| `FileCreate` | file appears |
| `DataExtend` | content written |
| `RenameOldName` / `RenameNewName` | rename — **two consecutive rows, same timestamp** |
| `FileDelete` | removed |
| `StreamChange` | ADS added or modified |
| `BASIC_INFO_CHANGE` | attributes or timestamps changed — **timestomping leaves this** |

A downloaded file's full lifecycle, from Streamer:

```
10:19:46   NQwpdhlm.zip.part                          FileCreate      ← browser temp
10:19:46   OBS-Studio-28.8KgRH_9b.1.2-...x64.part     RenameNewName   ← server-side temp
10:20:47   OBS-Studio-28.8KgRH_9b.1.2-...x64.part     DataExtend      ← download writing
10:20:48   OBS-Studio-28.1.2-Full-Installer-x64.zip   RenameNewName   ← original name
10:22:23   Obs Streaming Software.zip                 RenameNewName   ← user rename
```

Browsers write to `.part` (or a random name) while downloading and rename on completion. **"Original name" means the name once the download finished**, not the temporary.

**The `$J` has no path column.** Take the `Parent Entry Number` and resolve it against the `$MFT` to get `Parent Path`.

### Entry Number is not unique

NTFS recycles MFT record numbers. Each reuse increments a **Sequence Number**, and the real identifier is the pair.

```
Entry 129184 / Seq 2   →  unrelated file, deleted
Entry 129184 / Seq 3   →  unrelated file, deleted
Entry 129184 / Seq 8   →  the file you're after
```

Filtering on entry number alone returns rows from every file that ever held that record. Same failure mode as pivoting on PID instead of `ProcessGuid`.

---

## 3. Prefetch — evidence of execution

`C:\Windows\prefetch\*.pf`. Records the **last 8 executions** of each binary, a run count, and every file and directory the process touched in its first ~10 seconds.

```
PECmd.exe -d "<triage>\C\Windows\prefetch" --csv <out> --csvf pf.csv
PECmd.exe -f "<triage>\C\Windows\prefetch\NAME.EXE-XXXXXXXX.pf"
```

| Field | Use |
|---|---|
| `Executable Name` | **truncated at 29 characters** |
| `Hash` | hash of the **full path**, not the file contents |
| `Run Count`, `Last Run`, `Previous Run 0–6` | execution timeline |
| `Files Referenced` | resolves a truncated name to its full path |
| `Volumes` | shows a UNC volume if it ran from a share |

**The 29-character limit bites on deliberately long names.** Streamer's backdoor appeared as `LAT TAKEWODE LIBIGAX WELOJ JI`; the real path was 96 characters. Parsing the individual `.pf` and reading `Files Referenced` recovered it.

**The filename hash is a path hash.** `NAME.EXE-D8A6D943.pf`. The same binary run from two directories produces two `.pf` files with different hashes — useful for spotting copies of malware no longer on disk.

**Narrow by date first.** Filtering to the incident day cut 224 entries to 54, of which 52 were Windows components or the legitimate software installing as designed. The anomaly is visible against that baseline, not in isolation.

---

## 4. Amcache — hashes without the file

`C:\Windows\AppCompat\Programs\Amcache.hve`, a registry hive Windows keeps for application compatibility. It records executables the system has seen **including a SHA-1 hash** — one of the few artifacts that gives you a file hash when you don't have the file.

```
AmcacheParser.exe -f "<triage>\C\Windows\AppCompat\Programs\Amcache.hve" --csv <out> -i
```

| CSV | Contains |
|---|---|
| `UnassociatedFileEntries` | **standalone binaries** — portable tools, downloaded installers, malware |
| `AssociatedFileEntries` | executables tied to a registered installed program |
| `ProgramEntries` | installed programs |

Key fields: `SHA1`, `FullPath`, `Product Name`, `File Key Last Write Timestamp`.

**SHA-1 values carry four leading zeroes.** Strip them before comparing against VirusTotal.

**`Product Name` is worth reading.** A generic or nonsensical value on something claiming to be known software indicates trojanization.

**Absence from Amcache is not exoneration.** In Streamer the actual backdoor was *not* in Amcache; a second suspicious binary was. A short-lived process can execute without ever being registered — which makes it more interesting, not less.

---

## 5. Shellbags — evidence of navigation

Windows stores per-folder view preferences (window size, icon type, sort order). To do that it must remember which folders were opened, and that record is the artifact: **every folder ever browsed in Explorer**, including UNC paths, removable drives, and folders that no longer exist.

```
SBECmd.exe -d "<triage>\C\Users\<user>" --csv <out>
```

Two hives, different scopes — **parse both**:

| Hive | Records |
|---|---|
| `NTUSER.DAT` | local filesystem folders |
| `UsrClass.dat` | virtual shell objects — network locations, Control Panel, removable media |

In Streamer the network path turned up in `NTUSER.DAT` while `UsrClass.dat` held the local navigation, the opposite of what the documentation implies. Don't assume; open both.

`Absolute Path` is Explorer's view, not a filesystem path. Network locations look like this:

```
Desktop\Computers and Devices\<HOST>\<HOST>\Users\<user>\<folders…>
```

The host name appears **twice** — first as the network node, then as the share root. To convert to UNC, take everything from the second occurrence:

```
\\<HOST>\Users\<user>\<folders…>
```

`Shell Type` confirms the branch: `Network location` marks where the UNC begins.

---

## 6. LNK files — evidence of file access

`AppData\Roaming\Microsoft\Windows\Recent\*.lnk`, created when a file or folder is opened. Records the **target's** state at that moment.

```
LECmd.exe -d "<triage>\C\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv <out>
```

| Field | Use |
|---|---|
| `Local Path` / `Network share name` | full target path |
| `Target Created/Modified/Accessed` | the target's timestamps, not the LNK's |
| `File size (bytes)` | target size |
| `MFT entry/sequence #` | **the pair — pivots straight into `$MFT` and `$J`** |
| `Machine ID` | hostname where the LNK was created |
| `MAC Address` + vendor | NIC of that machine |

**`Drive type` distinguishes local from network.** A folder named "Share-Something" with `Drive type: Fixed storage media` and flag `VolumeIdAndLocalBasePath` is **local**. A real network target shows a `>> Network share information` block. The name is a hypothesis; the flag is the answer.

**A LNK is a snapshot at open time.** If the file was renamed afterwards, the LNK still holds the old name — cross-check against the `$J`.

---

## 7. Event logs

```
EvtxECmd.exe -d "<triage>\C\Windows\System32\winevt\Logs" --csv <out> --csvf evtx.csv
```

| EID | Log | Meaning |
|---|---|---|
| **4698** | Security | **scheduled task created** — payload holds the full XML |
| 4699 / 4702 | Security | task deleted / updated |
| 4697 | Security | service installed |
| 200 / 201 | TaskScheduler/Operational | task action started / completed |
| **3006** | DNS-Client/Operational | **query sent** — name only |
| **3008** | DNS-Client/Operational | **response** — includes resolved IP |
| 3009 / 1014 | DNS-Client/Operational | query failed / resolution timeout |
| 4624 / 4625 | Security | logon success / failure |

**3006 vs 3008 matters.** Use **3006** to find a domain — the query fires even when nothing resolves. Use **3008** to find an IP, since it carries `QueryResults`. Hunting a non-existent domain in 3008 is the wrong tool for the job.

**Scheduled task XML (4698)** holds `TaskName`, `Command`, `Arguments`, `Trigger`, `RunLevel` and the registering user. Note that the parser splits `Command` and `Arguments` at the first space — a path containing spaces appears artificially divided into a command plus arguments.

**Filter task names by action path, not by name.** A task called `COMSurrogate` (the display name of `dllhost.exe`) reads as system infrastructure. Any task whose `Command` points outside `System32` or `Program Files` deserves review regardless of what it is called.

---

## 8. Windows Firewall log

```
C:\Windows\System32\LogFiles\Firewall\pfirewall.log
```

Plain text, space-delimited, **not an event log** — no parser needed, and easy to forget it exists.

```
date time action protocol src-ip dst-ip src-port dst-port size tcpflags …
```

Gives source ports, direction and timing without network capture. Filtering on a known IP is often faster than converting the file to CSV.

**`pfirewall.log` records LOCAL time. `$MFT` and EVTX record UTC.** Normalize before building any timeline; in Streamer the offset was five hours.

---

## 9. Recovering content that isn't in the triage

Small files are stored inside the MFT record rather than in allocated clusters. Their content survives even when the file itself was never collected.

```
MFTECmd.exe -f "<triage>\C\$MFT" --csv <out> --csvf mft_rd.csv --dr
```

`--dr` writes every resident file to disk as an actual file, in a `Resident\` folder — it does not just add a column to the CSV.

Typical recoveries:

- **`:Zone.Identifier`** (~166 bytes) — the Mark-of-the-Web ADS, containing `ReferrerUrl` and `HostUrl`. This is where a download URL lives when the browser history is empty or wiped.
- **Notes and small text files** (a 57-byte note in Streamer).
- Ransom notes, config fragments, small scripts.

```
[ZoneTransfer]
ZoneId=3                  ← 3 = Internet zone
ReferrerUrl=http://…      ← the page the user was on
HostUrl=http://…          ← the exact download URL
```

---

## 10. Common errors and failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `$MFT`/`$J` filter returns rows from several unrelated files | Entry Number reused by NTFS | filter on **Entry + Sequence** |
| Small text file expected but not in the triage | it's **resident** in the `$MFT` | `MFTECmd --dr` |
| Executable name truncated in Prefetch | 29-character field limit | parse the `.pf`, read `Files Referenced` |
| Amcache SHA-1 doesn't match VirusTotal | four leading zeroes | strip them |
| Binary ran but isn't in Amcache | short-lived process, never registered | Prefetch and `$J` still have it |
| Searching a bogus domain by TLD finds nothing | the TLD **doesn't exist** at all | anchor on a timestamp instead |
| DNS filter returns thousands of rows | ad/tracking noise from browsing | narrow to the **exact minute** taken from another artifact |
| Timeline Explorer's search box doesn't reduce rows | it **highlights**, it doesn't filter | use the column filter or Edit Filter |
| Two date filters and the result grows | both conditions written as `>` | the second must be `<` |
| UNC path not in RunMRU, TypedPaths or Prefetch | it's **navigation**, not execution | shellbags |
| `$MFT` path rejected in PowerShell | `$` read as a variable | single quotes, or escape with a backtick |
| Extraction fails with `0x80004005` | Defender blocking NTFS metadata files or malware in the archive | folder exclusion + extract with 7-Zip |
| Chromium `History` locked or empty | SQLite needs write access for its journal | copy the file first |
| A command returns nothing instantly | stderr swallowed, or the tool failed | **instant empty ≠ empty after a scan** — check the exit path |

---

## 11. Golden rules

1. **Classify the question before opening a file.** Execution, navigation, file access, filesystem change, network, persistence — the category picks the artifact.
2. **Parse everything once.** KAPE Modules with `!EZParser` runs every Zimmerman tool in a single pass and sorts the output into `FileSystem`, `EventLogs`, `ProgramExecution`, `Registry`, `FileFolderAccess`. Parsing tool by tool means discovering halfway through that you need a CSV you never generated.
3. **A timestamp from another artifact beats any content filter.** One precise minute narrows everything downstream. In Streamer, TLD guessing, exclusion lists and status-code filtering all failed; filtering DNS to the minute the scheduled task was registered surfaced the C2 domain immediately.
4. **Build the baseline before calling something anomalous.** The anomaly is visible against the system's noise, not in isolation.
5. **Pivot on unique identifiers** — Entry+Sequence, `ProcessGuid`, prefetch hash. Never on a name.
6. **Read the content, not the name.** `ZxcvbnData\passwords.txt` is a Chromium dictionary. `Share-Wrkstn001` was a local folder. `COMSurrogate` was malware. The name is a hypothesis; the path, the flag and the payload settle it.

> Tool names, plugin names and flags change with versions. **The mapping from question to artifact category does not.**
