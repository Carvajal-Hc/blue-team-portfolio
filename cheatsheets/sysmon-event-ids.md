# Cheatsheet — Sysmon Event IDs for Endpoint Detection

Quick reference for the Sysmon events that carry the most investigative weight, built from the HTB Sherlock **Unit42** (an initial-access case using a masqueraded backdoor). Sysmon is the richest endpoint telemetry source on Windows: where the Security log tells you *an account did X*, Sysmon tells you *which process, from which parent, with which hash, over which network connection*.

Lab context: HTB Sherlock. Domains, hashes, IPs, and paths are training data.

---

## 1. The Sysmon events that matter most

| EID | Name | What it gives you | Why it matters |
|-----|------|-------------------|----------------|
| **1** | Process Creation | Image, **CommandLine**, ParentImage, **ProcessGuid**, Hashes, IntegrityLevel, User | The backbone of any investigation — full process lineage with command lines |
| **2** | File creation time changed | TargetFilename, old/new creation time | **Timestomping** — the only event that flags a deliberately altered timestamp |
| **3** | Network Connection | SourceIp/Port, **DestinationIp/Port**, Image | C2 beacons, downloads, lateral movement — ties a connection to a process |
| **5** | Process Terminated | Image, ProcessGuid | Self-termination of droppers; end of a process lifetime |
| **7** | Image Loaded | ImageLoaded, Signed, Signature | DLL side-loading, unsigned modules |
| **8** | CreateRemoteThread | SourceImage, TargetImage | Process injection |
| **11** | File Created | **TargetFilename**, Image, ProcessGuid | What a process dropped to disk — payloads, scripts, staged files |
| **13** | Registry Value Set | TargetObject, Details | Persistence via Run keys, config changes |
| **22** | DNS Query | **QueryName**, QueryResults, Image | Which domain a process resolved — delivery infrastructure |

**The four you reach for first:** **1** (what ran), **11** (what it dropped), **3** (where it called out), **22** (what it resolved).

---

## 2. The master pivot — ProcessGuid

The single most important habit: **pivot on `ProcessGuid`, not `Image`.**

- `Image` (the path/name) is reused, spoofed, and shared across many processes.
- `ProcessGuid` is **unique per process instance** across the whole log. It ties an EID 1 (the process starting) to its EID 3 (its network calls), EID 11 (its file writes), EID 22 (its DNS), and EID 5 (its termination).

```
EID 1  → note the ProcessGuid of the suspicious process
   ├─ filter EID 3  by that ProcessGuid → its C2 connections
   ├─ filter EID 11 by that ProcessGuid → what it dropped
   ├─ filter EID 22 by that ProcessGuid → what it resolved
   └─ filter EID 5  by that ProcessGuid → when it self-terminated
```

Also useful: **`ParentProcessGuid`** links a child back to its parent, letting you reconstruct the full chain (e.g. `explorer.exe → malware.exe → cmd.exe → ...`).

---

## 3. Key literals recovered (Unit42)

| Finding | Value |
|---------|-------|
| Malicious process | `Preventivo24.02.14.exe.exe` (double extension — masquerading) |
| Location | `\Downloads\` |
| Parent | `explorer.exe` (user double-clicked it → **T1204 User Execution**) |
| ProcessGuid | `817BDDF3-3684-65CC-2D02-000000001900` |
| Execution time (T0) | `2024-02-14 03:41:56.538` |
| Delivery | Dropbox (`dropboxusercontent.com`) |
| Connectivity check domain | `www.example.com` (dummy "am I online?" probe) |
| Timestomp | a PDF's creation time was altered (**EID 2**) |
| Dropped script | `once.cmd` |
| C2 | IP:port from **EID 3** |
| End of activity | dropper **self-terminated** (EID 5) |

**Signature of the case:** a file named `Preventivo24.02.14.exe.exe` — the **double extension** is the tell. Windows hides the real `.exe`, the user sees `...exe` and assumes a document. Launched from `explorer.exe`, it means a human double-clicked it.

---

## 4. Attack → detection mapping

| Attacker action | Sysmon signal | Field to read |
|-----------------|---------------|---------------|
| User runs a masqueraded file | EID 1, ParentImage = `explorer.exe` | `Image` (double extension), `CommandLine` |
| Downloads next stage | EID 3 / EID 22 | `DestinationIp`, `QueryName` |
| Drops a script/payload | EID 11 | `TargetFilename` |
| Hides its tracks (timestomp) | **EID 2** | `TargetFilename`, old vs new creation time |
| Beacons to C2 | EID 3 | `DestinationIp:Port` |
| Cleans up (self-terminate) | EID 5 | `ProcessGuid` matches the malware |

---

## 5. Timestomping — the EID 2 tell

EID 2 fires when a process **changes a file's creation timestamp** — something legitimate software almost never does. It is the endpoint-telemetry counterpart to the MFT `$SI` vs `$FN` mismatch (see the MFT Forensics cheatsheet).

- A malicious dropper often sets a payload's timestamps to blend with old system files.
- EID 2 records **both** the previous and the new creation time — the discrepancy is the evidence.
- If the log has EID 2 for a file in `\Downloads\` or `\Temp\`, treat that file as suspicious by default.

---

## 6. Living-off-trusted-services (delivery)

A recurring pattern across cases (Unit42 → Dropbox, and elsewhere Google Drive, Netlify, GitHub Pages): attackers host payloads on **legitimate cloud services** so the domain has good reputation and won't be blocked.

- Watch **EID 22** (`QueryName`) and **EID 3** (`DestinationIp`) for resolutions to `*.dropboxusercontent.com`, `storage.googleapis.com`, `*.netlify.app`, `raw.githubusercontent.com` originating from unusual processes.
- The domain being "trusted" is exactly why it evades reputation filtering — the anomaly is the **process** making the request, not the domain itself.
- The `www.example.com` probe in Unit42 is a separate tell: malware often checks a benign, guaranteed-up domain first to confirm internet access before contacting real C2.

---

## 7. Hunting queries (Splunk-style)

**Masqueraded execution from a user folder:**
```
EventCode=1 ParentImage="*\\explorer.exe" Image="*\\Downloads\\*"
| table _time, Image, CommandLine, ProcessGuid, Hashes
```

**Follow one process across all its activity:**
```
(EventCode=1 OR EventCode=3 OR EventCode=11 OR EventCode=22 OR EventCode=5)
ProcessGuid="<GUID>"
| sort _time
```

**Timestomping:**
```
EventCode=2
| table _time, Image, TargetFilename, PreviousCreationUtcTime, CreationUtcTime
```

**Suspicious DNS to trusted-hosting services:**
```
EventCode=22 (QueryName="*dropboxusercontent*" OR QueryName="*storage.googleapis*" OR QueryName="*netlify*")
| table _time, Image, QueryName
```

---

## 8. Field & time notes

- **UTC.** Sysmon `UtcTime` is already UTC — report it as-is. Sub-second precision (`.538`) matters for ordering rapid process chains.
- **CommandLine is the crown jewel.** Detection here is argument inspection, not binary identification — the binary is often a trusted or renamed one.
- **Hashes** (SHA256/IMPHASH) in EID 1 are ready-made IoCs; IMPHASH helps cluster variants of the same malware family.
- **IntegrityLevel = High** on a user-launched process signals successful elevation (often via a UAC-bypass or `RunAs` in the launch command).

---

## 9. Golden rule

**Pivot on ProcessGuid, read the CommandLine.** Sysmon's power is lineage: one unique process identifier ties together everything a piece of malware did — what it ran, dropped, resolved, connected to, and when it died. Chase the identifier, not the name.
