# Blue Team Portfolio — Carvajal

Defensive security work: DFIR investigations, threat hunting, malware analysis, and detection engineering. Each case reconstructs an attack from forensic evidence and documents **how each technique is detected** — the analyst's real job — not just how it happened.

Preparation work for the **HTB Certified Defensive Security Analyst (CDSA)** certification. All analysis is performed on controlled lab environments (HTB Sherlocks and HTB Academy modules); systems, accounts, addresses, hashes, and data are fictitious and do not correspond to any production infrastructure.

---

## Repository structure

```
blue-team-portfolio/
├── dfir/                    Incident investigations — full attack chains (CDSA report format)
├── threat-hunting/          Proactive hunts and hypothesis-driven detection
├── malware-analysis/        Static and dynamic analysis of malicious binaries
├── detection-engineering/   Sigma / YARA rules, SIEM queries, multi-technique assessments
└── cheatsheets/             Cross-cutting reference — telemetry, tooling, detection signatures
```

The folder reflects the **discipline** of the work. Investigations with collected evidence get their own subfolder (report + `evidence/`); cheatsheets are single reference files shared across disciplines.

---

## DFIR — investigations

Incident reconstruction from a provided evidence package. Each case follows the CDSA reporting structure: executive summary → technical analysis by phase → IoCs → MITRE mapping → recommendations → command appendix, with supporting screenshots.

| Case | Difficulty | Attack | Key techniques | Report |
|------|-----------|--------|----------------|--------|
| **LogForge** | Medium | FileFix → ransomware | FileFix (T1204.004), masquerading, AutoIt, EDR/AV discovery, Startup persistence, `$MFT`-resident note recovery | [report](dfir/logforge-filefix/) |
| **Campfire-1** | Very Easy | Kerberoasting | 4769/0x17, PowerView, Rubeus, workstation↔DC correlation | *see cheatsheet* |
| **Campfire-2** | Very Easy | AS-REP Roasting | 4768/Pre-Auth 0, IP-correlation attribution, share access (5140) | *see cheatsheet* |
| **Unit42** | Very Easy | Initial access (backdoor) | Sysmon EIDs, ProcessGuid pivot, masquerading, timestomp | *see cheatsheet* |
| **BFT** | Very Easy | Delivery + stager | MFT forensics, `$SI` vs `$FN`, resident data, Zone.Identifier | *see cheatsheet* |

---

## Threat hunting

*Hypothesis-driven hunts and proactive detection. (Coming soon.)*

---

## Malware analysis

*Static and dynamic analysis of malicious samples. (Coming soon.)*

---

## Detection engineering

Multi-technique assessments and detection content (rules, queries) mapped to MITRE ATT&CK.

| Work | Scope | Status |
|------|-------|--------|
| **Windows Attacks & Defense (EAGLE.LOCAL)** | 14 Active Directory attack vectors (Kerberoasting, AS-REP, GPP, DCSync, Golden Ticket, delegation, coercion, NTLM Relay, ADCS ESC1/ESC8, ACL abuse) with associated detection | In progress |

---

## Cheatsheets

Per-technique and per-tool reference material — Event IDs, differentiating fields, and detection signatures. Cross-cutting, so kept outside the discipline folders.

| Cheatsheet | Content | Source |
|------------|---------|--------|
| [Kerberos Attack Detection](cheatsheets/kerberos-attacks-detection.md) | Kerberoasting (4769/0x17) + AS-REP Roasting (4768/Pre-Auth 0), attribution pivot, SIEM rules | Campfire-1, Campfire-2 |
| [Sysmon Event IDs](cheatsheets/sysmon-event-ids.md) | Endpoint telemetry (EID 1/2/3/5/11/22), ProcessGuid pivot, attack→event mapping | Unit42 |
| [MFT Forensics](cheatsheets/mft-forensics.md) | Timestomping (`$SI` vs `$FN`), resident data, Zone.Identifier, offset arithmetic | BFT |

---

## Methodology

Every investigation is guided by the same analytical principles:

- **The anomaly is in the distribution, not the volume** — what appears once and isolated, against the system's background noise.
- **Pivot on unique identifiers** — `ProcessGuid`, `EntryNumber`, `Client Address`, SID read from source — rather than chasing event categories.
- **Empirical validation of every finding** — the literal comes from the artifact, verified, never reconstructed from memory.
- **Attack ↔ defense bridge** — for each offensive technique, the Event ID, differentiating field, and detection query (SPL / PowerShell / KQL) that surfaces it in a SOC.

---

## Tooling

**Zimmerman Tools** (EvtxECmd, MFTECmd, PECmd, RECmd, Registry Explorer, Timeline Explorer) · **KAPE** (triage) · **DB Browser for SQLite** (browser history) · **Chainsaw / Hayabusa** (Sigma-based triage) · **HxD** · **Volatility** (memory) · **Wireshark / Zeek / Suricata** (network) · **YARA / Sigma** (detection) · **Splunk** (SIEM)

## Frameworks

Detections mapped to **MITRE ATT&CK**. Reports structured following the **Security Incident Reporting** methodology from the HTB Academy SOC Analyst path.

---

*Portfolio under active development. Discipline folders are added as the first case in each area is completed.*
