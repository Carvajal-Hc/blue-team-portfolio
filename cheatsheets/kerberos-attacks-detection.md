# Cheatsheet — Kerberos Attack Detection (Kerberoasting & AS-REP Roasting)

Detection reference for two Kerberos credential-access techniques, built from the HTB Sherlocks **Campfire-1** (Kerberoasting) and **Campfire-2** (AS-REP Roasting). Both are investigated from the **Domain Controller Security event log** (`Security.evtx`), parsed with **EvtxECmd** and analysed in **Timeline Explorer**.

> Lab context: HTB Sherlocks. Domains, accounts, IPs, and SIDs are training data.

---

## 1. The two techniques at a glance

| | **Kerberoasting** | **AS-REP Roasting** |
|---|---|---|
| Ticket requested | **TGS** (service ticket) | **TGT** (auth ticket) |
| Event ID | **4769** (service ticket requested) | **4768** (auth ticket requested) |
| Precondition | Account has an **SPN** (service account) | Account has **pre-auth disabled** |
| Differentiating field | `Ticket Encryption Type = 0x17` (RC4) | `Pre-Authentication Type = 0` |
| What the attacker cracks | Service account password (from TGS) | User password (from AS-REP) |
| Does it authenticate the attacker? | No | No |
| MITRE ATT&CK | **T1558.003** | **T1558.004** |

**The core idea both share:** the attacker requests a Kerberos ticket encrypted with **RC4 (`0x17`)** so it can be cracked offline. Neither technique authenticates the attacker, so **attribution requires correlation**, not the attack event itself.

---

## 2. Kerberoasting (Campfire-1) — detection

**What happens.** The attacker enumerates accounts with a Service Principal Name (SPN), requests a **TGS** for each, and receives a service ticket encrypted with the service account's password hash. Requesting RC4 (`0x17`) makes the hash crackable offline (e.g. Hashcat mode 13100).

**Primary signal — Event 4769:**

```
EventID              = 4769   (A Kerberos service ticket was requested)
Ticket Encryption Type = 0x17 (RC4-HMAC — the crackable, downgraded cipher)
Service Name         = <the SPN / service account targeted>
Client Address       = <the workstation the request came from>
```

**How to isolate it (Timeline Explorer):**
- Filter `EventId = 4769`.
- Look for `Ticket Encryption Type = 0x17` (in a modern, healthy domain most tickets are AES `0x12`; RC4 requests stand out).
- Read `Service Name` for the targeted account and `Client Address` for the source host.

**Key literals recovered (Campfire-1):**

| Task | Finding |
|------|---------|
| First roast time (UTC) | `2024-05-21 03:18:09` |
| Targeted service | `MSSQLService` |
| Source workstation IP | `172.17.79.129` (from `::ffff:172.17.79.129`) |
| Enumeration tool loaded | `PowerView.ps1` |
| Roasting tool | `C:\Users\Alonzo.Spire\Downloads\Rubeus.exe` |
| Credential dumping | **same Rubeus** binary (LastRun `2024-05-21 03:18:08`) |

**Lesson.** One tool covered multiple techniques — Rubeus performed both the roasting **and** the credential dumping. Don't assume a separate tool per technique; check whether one binary explains several findings before hunting for another.

---

## 3. AS-REP Roasting (Campfire-2) — detection

**What happens.** The attacker targets accounts with **Kerberos pre-authentication disabled**. Because pre-auth is off, anyone can request that user's AS-REP **without proving identity**, and the reply contains material encrypted with the user's password hash — crackable offline.

**Primary signal — Event 4768:**

```
EventID                 = 4768   (A Kerberos authentication ticket (TGT) was requested)
Pre-Authentication Type = 0      (EvtxECmd maps this to "Logon without Pre-Authentication")
Ticket Encryption Type  = 0x17   (RC4)
Target User Name        = <the vulnerable account>
Client Address          = <the workstation the request came from>
```

**How to isolate it (Timeline Explorer):**
- Filter `EventId = 4768`.
- The malicious one shows **Pre-Authentication Type 0**. Note: EvtxECmd renders this as the string **"Logon without Pre-Authentication"**, not the number `0` — searching for `0` will not find it. Filter the payload column for `without Pre-Auth`.
- Normal logons show `PA-ENC-TIMESTAMP` (pre-auth present); the anomaly is the single account without it.

**Key literals recovered (Campfire-2):**

| Task | Finding |
|------|---------|
| Attack time (UTC) | read from `TimeCreated` of the 4768 with Pre-Auth 0 |
| Targeted (victim) account | `arthur.kyle` |
| Target SID | read from the event payload (the **user** SID, not the `ServiceSid` of krbtgt) |
| Source workstation IP | from `Client Address` (`::ffff:...` → the IPv4) |
| Compromised account used by attacker | `happy.grunwald` |

**SID trap.** A 4768 contains **two** SIDs: a `ServiceSid` (krbtgt — ignore it) and the **target user SID**. The task wants the user's SID. Reading the krbtgt ServiceSid is the classic wrong answer.

---

## 4. The attribution pivot (the real IR lesson)

Neither technique authenticates the attacker. The malicious 4768/4769 tells you **what** happened and **to whom**, but not **who did it**. The attacker account is found by correlation:

```
Client Address of the malicious event  (the workstation IP)
   └─ what OTHER accounts authenticated normally from that same IP, around the same time?
      └─ the one that is NOT the victim = the compromised account the attacker is using
```

In Campfire-2 this surfaced **`happy.grunwald`**: filtering all events from the attack workstation IP showed that account requesting a TGS (4769) and accessing shares (5140) seconds after the AS-REP roast — including a **`\\*\DC-Confidential`** share (`C:\Shares\DC-Confidential`). That share access is the *impact* and raises severity from "credential theft attempt" to "compromised account accessed confidential data".

**Rule:** when the technique doesn't authenticate the attacker, pivot on the **Client Address** and read the surrounding authenticated activity (4624 / 4769 / 5140) to attribute the actor.

---

## 5. Field & encoding gotchas

- **Local time vs UTC.** Event Viewer displays timestamps in the host's local time; the XML `SystemTime` (and EvtxECmd's CSV) is **UTC**. Always report UTC — parse with EvtxECmd rather than reading the Viewer to avoid the offset trap.
- **`::ffff:` prefix.** Client addresses often appear as IPv4-mapped IPv6 (`::ffff:172.17.79.129`). The answer is the IPv4 portion.
- **EvtxECmd string mapping.** Pre-Auth `0` is shown as **"Logon without Pre-Authentication"**; encryption types map to `0x17` (RC4) / `0x12` (AES256). Filter on the mapped strings, not the raw numbers.
- **Distribution over volume.** In both cases the malicious event was a single anomaly against dozens of routine tickets (DC machine account, current Administrator). One odd `0x17` / one Pre-Auth 0 beats the background noise.

---

## 6. Encryption type reference

| Value | Cipher | Meaning in this context |
|-------|--------|-------------------------|
| `0x1` / `0x3` | DES | Legacy, very weak (rare) |
| `0x11` | AES128 | Modern, healthy |
| `0x12` | AES256 | Modern, healthy — the expected default |
| `0x17` | **RC4-HMAC** | **Downgraded — the roasting signal** |
| `0x18` | RC4 (exported) | Also weak |

A request for `0x17` when the domain otherwise uses AES is a deliberate downgrade to enable offline cracking — the single most useful field for both techniques.

---

## 7. SIEM / hunting queries

**Kerberoasting (Splunk-style):**
```
EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Service_Name, Client_Address, Account_Name
```
Tune out known service-to-service traffic; alert on RC4 TGS requests to sensitive SPNs, or a single client requesting many distinct SPNs.

**AS-REP Roasting:**
```
EventCode=4768 Pre_Authentication_Type=0 Ticket_Encryption_Type=0x17
| stats count by Target_User_Name, Client_Address
```
Almost no account should have pre-auth disabled; any 4768 with Pre-Auth 0 toward a privileged/old account is high-suspicion.

**Attribution follow-up (either technique):**
```
Client_Address="<attack workstation IP>"
| table _time, EventCode, Account_Name, Service_Name, Share_Name
| sort _time
```

---

## 8. Golden rule

**The Kerberos attack event names the victim, never the actor.** `0x17` and `Pre-Auth 0` are the technique signatures; attribution comes from pivoting on the `Client Address` and reading the normal authenticated activity around it. Detection = the encryption/pre-auth anomaly; attribution = the correlation.
