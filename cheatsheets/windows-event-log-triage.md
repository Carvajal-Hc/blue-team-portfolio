# Cheatsheet — Windows Event Log Triage (native channels)

Reference for analysing the built-in Windows event logs on a single host, built from the HTB Sherlock **LogJammer** (a Windows Event Log analysis case covering logon, firewall, audit policy, scheduled tasks, Defender, PowerShell, and log clearing). Where **Sysmon** (see that cheatsheet) is telemetry you install, these are the channels Windows writes by default — and each one answers a *different* question. The skill is knowing which channel and Event ID answers what. Parsed with **EvtxECmd**, analysed in **Timeline Explorer**.

Lab context: HTB Sherlock. Hosts, users, IPs, and paths are training data.

---

## 1. The channels and the Event IDs that matter

Each `.evtx` is a separate channel. Filter the channel to the question, then the Event ID.

### Security (`Security.evtx`)

| EID | What it is | What it answers / detects |
|-----|-----------|---------------------------|
| **4624** | Successful logon | Who logged in, when, **how** (read `Logon Type`) |
| **4625** | Failed logon | Password spraying, brute force, invalid stolen creds |
| **4634 / 4647** | Logoff | Session end |
| **4672** | Special privileges assigned | Admin-equivalent logon |
| **4688** | Process creation | Command line (if command-line auditing is on) |
| **4698** | Scheduled task **created** | Persistence — embeds the full task XML (name, command, args) |
| **4719** | Audit policy changed | Defense evasion — which subcategory, success/failure added/removed |
| **1102** | Security log cleared | Anti-forensics (fires only for the Security log) |

### Windows Firewall (`...Windows Firewall With Advanced Security/Firewall`)

| EID | What it is |
|-----|-----------|
| **2004** | A rule was **added** |
| **2005** | A rule was **modified** |
| **2006** | A rule was **deleted** |
| **2033** | All rules cleared |

### Windows Defender (`...Windows Defender/Operational`)

| EID | What it is |
|-----|-----------|
| **1116** | Malware **detected** (threat name + path; may show `Action = Not Applicable`) |
| **1117** | **Action taken** on malware (Quarantine / Remove / Allow / Block) |
| **5001** | Real-time protection **disabled** (evasion) |
| **1121** | ASR rule blocked an action |

### PowerShell (`...PowerShell/Operational`, and classic `Windows PowerShell`)

| EID | Channel | What it is |
|-----|---------|-----------|
| **4104** | Operational | **Script Block Logging** — the full command/script text as executed |
| **4103** | Operational | Module/pipeline logging — parameters, fragmented |
| 400 / 800 | Classic | Engine start / pipeline execution details (`HostApplication`) |

### System (`System.evtx`)

| EID | What it is |
|-----|-----------|
| **104** | An event log was **cleared** — **names the channel** that was cleared |
| **7045** | A service was installed (persistence / lateral movement) |
| **7040** | Service start type changed (e.g. disabling a defense) |

---

## 2. Logon Type reference (Event 4624)

A 4624 is meaningless without its `Logon Type` — it's the difference between a person and background noise.

| Type | Meaning | Reads as |
|------|---------|----------|
| **2** | Interactive | Someone at the keyboard (console) |
| **3** | Network | SMB/share access, remote auth — service noise |
| **4** | Batch | Scheduled task context |
| **5** | Service | A service starting — noise |
| **7** | Unlock | Unlocked an existing session (not a *new* login) |
| **8** | NetworkCleartext | Creds sent in cleartext (e.g. basic auth) |
| **9** | NewCredentials | `runas /netonly` — pass-the-hash tooling often uses this |
| **10** | RemoteInteractive | **RDP** |
| **11** | CachedInteractive | Logged in with cached creds (DC unreachable) |

**"Logged into his computer" = Type 2** (or Type 10 if the access was remote/RDP). Drop Types 3/5 and the `SYSTEM` / `LOCAL SERVICE` / `NETWORK SERVICE` / `DWM` accounts — they're the machine logging into itself.

---

## 3. The workflow & the master habit

```
EvtxECmd.exe -d "<folder of .evtx>" --csv "<out>" --csvf case.csv   → one combined CSV
   → open in Timeline Explorer → filter Channel/Event Id → read the payload
```

**Anchor on the incident window, then let distribution do the work.** Most native-log Event IDs are noisy because Windows generates them in bulk (firewall rules on every install, log rotations on schedule, hundreds of 4104 for console housekeeping). The attacker's event is the **isolated one**, off the bulk clusters, inside the incident window you established from the first logon.

- **The anomaly is in the distribution, not the volume.** 490 firewall `2004` events, and the malicious one is a single manual rule off the install clusters. 14 `104` clears, and 13 are one wrong day.
- **Anchor everything to the first interactive logon time.** Once you have the 4624 timestamp, every later action hangs off that session's window.

---

## 4. Key literals recovered (LogJammer)

| Finding | Value | Source |
|---------|-------|--------|
| First interactive logon (UTC) | `2023-03-27 14:37:09` | Security 4624, Type 2 |
| Malicious firewall rule | `Metasploit C2 Bypass`, Outbound, TCP 4444, Allow | Firewall 2004 |
| Rule created via | `mmc.exe` (manual, `wf.msc` snap-in) | Firewall 2004 `ModifyingApplication` |
| Audit subcategory changed | `Other Object Access Events` (GUID `0cce9227-69ae-11d9-bed3-505054503030`) | Security 4719 |
| Scheduled task | `\HTB-AUTOMATION`, daily 09:00 | Security 4698 |
| Task command / args | `...\Desktop\Automation-HTB.ps1` · `-A cyberjunkie@hackthebox.eu` | Security 4698 |
| Tool flagged | `SharpHound` (`HackTool:PowerShell/SharpHound.B`, `...MSIL/SharpHound!MSR`) | Defender 1116 |
| Malware path | `C:\Users\CyberJunkie\Downloads\SharpHound-v1.1.0.zip` | Defender 1116 |
| AV action | `Quarantine` (with `Error Code 0x80508023` → remediation failed) | Defender 1117 |
| PowerShell command | `Get-FileHash -Algorithm md5 .\Desktop\Automation-HTB.ps1` | PowerShell 4104 |
| Log cleared | `...Windows Firewall With Advanced Security/Firewall` | System 104 |

Same-actor correlation: the firewall rule's `ModifyingUser` SID and the scheduled task's `SubjectUserSid` are identical (`...-1001`) — one account tied to both actions by SID, not by name.

---

## 5. The events with a trick to them

### 4719 — audit policy: read the GUID, not the string
The payload gives the subcategory as `%%` codes (`SubcategoryId %%12804`) and a `SubcategoryGuid`. The **GUID is the reliable identifier** — same on any Windows box, language-independent. Resolve `%%12804` / `0cce9227-...` to the readable name (`auditpol /list /subcategory:*` maps them). Report the subcategory name **without** the "Audit" prefix. Also read `AuditPolicyChanges`: `%%8448` Success removed, `%%8449` Success added, `%%8450` Failure removed, `%%8451` Failure added.

### 1116 vs 1117 — detection is not action
Defender splits **detection** (1116) from **remediation** (1117). The 1116 often shows `Action = Not Applicable` — it only found the threat. The real action lives in **1117** (`Action ID 2 = Quarantine`, etc.). Reading the action off the 1116 is the classic wrong answer.
**High-value tell:** a 1117 with `Action = Quarantine` **and** a non-zero `Error Code` (e.g. `0x80508023`, "could not find the malware on this device") means remediation *failed* — the file was moved/extracted before quarantine landed. The threat may still be live. Escalate.

### 4104 — do not filter by `Level = Warning`
PowerShell tags *some* suspicious blocks as Warning, but a syntactically clean command (no obfuscation) logs as **Information**. Filtering by Warning silently hides it. Hunt by **`ScriptBlockText` content** (`DownloadString`, `IEX`, `-enc`, `Invoke-Expression`, a known filename) and by time window — not by level. Ignore `ScriptBlockText: prompt` (console redraw noise).

### 104 vs 1102 — which one names the cleared log
`1102` fires **only** when the *Security* log is cleared and doesn't name a channel. `104` (System) fires for **any** channel and **names it** in the payload (`Channel` field). If the question is *which* log was cleared, `104` is the source. Clearing a log generates its own event in a *different* log — which is why the trace survives.

---

## 6. Attack → detection mapping

| Attacker action | Signal | Field to read |
|-----------------|--------|----------------|
| Logs in at the keyboard | Security 4624, Type 2 | `TargetUserName`, `LogonType`, `SystemTime` |
| Opens a firewall port for C2 | Firewall 2004 | `RuleName`, `Direction`, `RemotePorts`, `ModifyingApplication` |
| Blinds auditing | Security 4719 | `SubcategoryGuid`, `AuditPolicyChanges` |
| Establishes persistence | Security 4698 | task XML: `<Command>`, `<Arguments>`, trigger |
| Runs offensive tooling | Defender 1116 / 1117 | `Threat Name`, `Path`, `Action Name`, `Error Code` |
| Executes via PowerShell | PowerShell 4104 | `ScriptBlockText` |
| Clears its tracks | System 104 (or Security 1102) | `Channel`, `SubjectUserName` |

---

## 7. Field, time & tool gotchas

- **UTC from the XML, not the column.** `Get-WinEvent` and the friendly view show *local* time. The authoritative UTC value is the `SystemTime` attribute in the event XML (trailing `Z`). EvtxECmd's CSV is already UTC. Never trust a converted column for a UTC answer.
- **Timeline Explorer date filters use `=`, not `Contains`.** The `Time Created` column is typed as datetime, so `= 2023-03-27 00:00:00` matches only that exact instant (→ empty). To scope by day, **sort** the column and use the top-right "Enter text to search…" box (plain-text navigation, ignores column type), or filter a text column instead.
- **`%%NNNN` codes** are string pointers — resolve them (audit subcategories, `AuditPolicyChanges`). Don't report the raw code.
- **`::ffff:` prefix** on client addresses is IPv4-mapped IPv6 — the answer is the IPv4 part.
- **Defender `Path` is messy** — strips down to the clean on-disk file. `containerfile:_` / `file:_` / `webfile:_` prefixes plus a download URL; the real artifact is usually the container (the ZIP), and `webfile:_` gives you the download provenance for free.
- **Exact-value hygiene** — give what the source asks, nothing extra. Subcategory *without* "Audit"; timestamp in 24h `YYYY-MM-DD HH:MM:SS` (the `p. m.` / 12h format gets rejected on form, not content).

---

## 8. SIEM / hunting queries (Splunk-style)

**Manual firewall rule for C2:**
```
EventCode=2004 (Direction=Outbound OR Direction=2)
| search RemotePorts IN (4444,5555,8080) OR ModifyingApplication="*mmc.exe"
| table _time, RuleName, RemotePorts, ModifyingApplication, ModifyingUser
```

**Audit policy tampering (rare = alert on all):**
```
EventCode=4719
| table _time, SubjectUserName, SubcategoryGuid, AuditPolicyChanges
```

**Scheduled task running a script from a user folder:**
```
EventCode=4698
| search TaskContent="*.ps1*" OR TaskContent="*\\Users\\*\\Desktop\\*"
| table _time, SubjectUserName, TaskName, TaskContent
```

**Failed AV remediation (still-live threat):**
```
EventCode=1117 Action_Name=Quarantine Error_Code!=0x00000000
| table _time, Threat_Name, Path, Action_Name, Error_Code
```

**PowerShell by content, not level:**
```
EventCode=4104 (ScriptBlockText="*DownloadString*" OR ScriptBlockText="*IEX*"
  OR ScriptBlockText="*-enc*" OR ScriptBlockText="*Invoke-Expression*")
| table _time, User, ScriptBlockText
```

**Log cleared (incident until proven otherwise):**
```
(EventCode=104 OR EventCode=1102)
| table _time, EventCode, SubjectUserName, Channel
```

---

## 9. Golden rule

**Each native channel answers a different question — match the channel to the question, anchor on the incident window, and read the raw field, not the friendly view.** Security tells you *who logged in and what policy changed*; Firewall *what ports opened*; Defender *what tooling was caught and whether remediation actually completed*; PowerShell *what ran* (by content, not level); System *what log got wiped*. The attacker's event is the isolated one off the bulk clusters, and the act of hiding — clearing a log, changing a policy — writes its own record in a channel you haven't cleared yet.
