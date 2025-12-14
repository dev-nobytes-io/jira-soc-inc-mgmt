# Kerberos Attack Detections

## Overview

Detections for Kerberos-based attacks including Kerberoasting, Golden Ticket, Silver Ticket, and other Kerberos abuse techniques.

---

## DET-KRB-001: Kerberoasting Detection

### Overview
- **Detection ID**: DET-KRB-001
- **MITRE ATT&CK**: T1558.003 (Kerberoasting)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs

### Description

Detects Kerberoasting attacks where attackers request service tickets for service accounts to crack offline. Identifies abnormal TGS (Ticket Granting Service) request patterns.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4769
| where Service_Name!="*$" AND Service_Name!="krbtgt"
| eval Ticket_Encryption_Type_hex=Ticket_Encryption_Type
| eval Ticket_Encryption=case(
    Ticket_Encryption_Type="0x17", "RC4-HMAC",
    Ticket_Encryption_Type="0x12", "AES256-CTS-HMAC-SHA1-96",
    Ticket_Encryption_Type="0x11", "AES128-CTS-HMAC-SHA1-96",
    1=1, "Other"
)
| where Ticket_Encryption="RC4-HMAC"
| stats count dc(Service_Name) as unique_services values(Service_Name) as services by Account_Name, src_ip
| where unique_services > 5
| eval description="Possible Kerberoasting - Multiple service ticket requests with RC4 encryption"
| table _time, Account_Name, src_ip, count, unique_services, services
| sort - count
```

### Notable Event Configuration

```
Title: Kerberoasting Attack Detected - $Account_Name$
Description: User $Account_Name$ from $src_ip$ requested $unique_services$ service tickets using RC4 encryption within short time period. This is consistent with Kerberoasting attack pattern.
Services requested: $services$
Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1558.003

Recommended Actions:
1. Disable account $Account_Name$ immediately
2. Investigate source IP $src_ip$ for compromise
3. Reset passwords for all service accounts listed
4. Review service account configurations
5. Implement long, complex passwords for SPNs
6. Enable AES encryption for Kerberos
7. Escalate to Incident Response Team
```

### Enhanced Detection (Sysmon)

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(GetUserSPNs|Invoke-Kerberoast|Rubeus.*kerberoast)")
| table _time, User, ComputerName, CommandLine, ParentImage, ParentCommandLine
| eval description="Kerberoasting tool execution detected"
```

### False Positives

1. **Legitimate Service Ticket Requests**: Some applications may request multiple service tickets
2. **Monitoring Tools**: Tools that enumerate services
3. **Old Systems**: Legacy systems may still use RC4

**Tuning**:
- Adjust threshold (default: >5 services)
- Whitelist known monitoring accounts
- Focus on RC4 encryption (indicator of older attack tools)

### Response Actions

**Immediate**:
1. Disable requesting account
2. Reset SPN account passwords
3. Investigate requesting system

**Investigation**:
1. Check for offline password cracking
2. Review service account password strength
3. Implement password rotation for SPNs
4. Enable AES encryption

**Playbook**: [Kerberoasting Response](../../playbooks/active-directory/kerberoasting.md)

### SOAR Integration

```python
# Kerberoasting response playbook

# 1. Disable account
phantom.disable_user(user=account_name)

# 2. Get all SPN accounts requested
spn_accounts = parse_services(services)

# 3. Force password reset for SPNs (requires approval)
for spn in spn_accounts:
    phantom.create_password_reset_task(account=spn, priority="high")

# 4. Notify security team
phantom.send_alert(
    severity="high",
    message=f"Kerberoasting detected: {account_name} requested {unique_services} service tickets"
)

# 5. Investigate source
phantom.isolate_endpoint(ip=src_ip)
phantom.collect_forensics(ip=src_ip)
```

---

## DET-KRB-002: Golden Ticket Detection

### Overview
- **Detection ID**: DET-KRB-002
- **MITRE ATT&CK**: T1558.001 (Golden Ticket)
- **Severity**: Critical
- **Data Sources**: Windows Security Event Logs

### Description

Detects potential Golden Ticket attacks by identifying anomalous Kerberos TGT characteristics, including unusual encryption types, ticket lifetimes, and authentication patterns.

### SPL Query - Abnormal Ticket Lifetime

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4768
| eval ticket_lifetime_hours = (tonumber(TicketOptions) / 3600)
| where ticket_lifetime_hours > 10
| search Account_Name!="*$"
| table _time, Account_Name, Client_Address, ticket_lifetime_hours, Ticket_Encryption_Type
| eval description="Abnormal Kerberos ticket lifetime - possible Golden Ticket"
| sort - ticket_lifetime_hours
```

### SPL Query - Encryption Downgrade

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4768
| eval Ticket_Encryption=case(
    Ticket_Encryption_Type="0x17", "RC4",
    Ticket_Encryption_Type="0x12", "AES256",
    Ticket_Encryption_Type="0x11", "AES128",
    1=1, "Other"
)
| where Ticket_Encryption="RC4"
| search Account_Name!="*$"
| lookup known_rc4_accounts.csv Account_Name OUTPUT expected
| where isnull(expected)
| table _time, Account_Name, Client_Address, Ticket_Encryption, Service_Name
| eval description="RC4 encryption for non-legacy account - possible Golden Ticket"
```

### SPL Query - TGT Request Pattern Anomaly

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4768
| stats count by Account_Name, Client_Address
| where count > 20
| table Account_Name, Client_Address, count
| eval description="Excessive TGT requests - possible Golden Ticket generation"
```

### Notable Event Configuration

```
Title: CRITICAL - Golden Ticket Attack Indicators for $Account_Name$
Description: Multiple indicators of Golden Ticket attack detected for account $Account_Name$:
- Abnormal ticket lifetime
- Encryption downgrade to RC4
- Unusual TGT request pattern
Source: $Client_Address$

This is a CRITICAL security incident indicating potential domain compromise.

Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1558.001

Recommended Actions:
1. IMMEDIATELY isolate $Client_Address$
2. Disable $Account_Name$ if not krbtgt
3. Investigate ALL domain controllers
4. Reset krbtgt password TWICE (full procedure)
5. Check for persistence mechanisms
6. Full domain compromise investigation
7. ESCALATE TO IR TEAM AND CISO IMMEDIATELY
```

### Response Actions

**CRITICAL - Domain Compromise Scenario**:

1. **Immediate Containment**:
   - Isolate suspected compromised systems
   - Disable compromised accounts
   - Alert all security staff

2. **Evidence Preservation**:
   - Capture memory from DCs
   - Preserve all Kerberos logs
   - Document timeline

3. **Krbtgt Password Reset** (Requires careful planning):
   ```powershell
   # First reset
   Set-ADAccountPassword -Identity krbtgt -Reset

   # Wait for replication (minimum 10 hours)

   # Second reset
   Set-ADAccountPassword -Identity krbtgt -Reset
   ```

4. **Full Investigation**: Treat as full domain compromise

### SOAR Integration

```python
# Golden Ticket critical response

# 1. Immediate notifications
phantom.send_critical_alert(
    recipients=["soc-critical", "ciso", "ir-team"],
    message="CRITICAL: Golden Ticket attack detected - possible domain compromise"
)

# 2. Automatic containment
phantom.isolate_endpoint(ip=client_address)

# 3. Disable account (if not krbtgt)
if account_name != "krbtgt":
    phantom.disable_user(user=account_name)

# 4. Create critical incident
phantom.create_incident(
    severity="critical",
    title="Golden Ticket Attack - Domain Compromise",
    assign_to="IR Team Lead",
    auto_escalate=True
)

# 5. Evidence collection
phantom.collect_memory_dump(hosts=domain_controllers)
phantom.preserve_logs(source="kerberos", hours=72)

# 6. War room
phantom.create_war_room(incident_id=incident_id)
```

---

## DET-KRB-003: Silver Ticket Detection

### Overview
- **Detection ID**: DET-KRB-003
- **MITRE ATT&CK**: T1558.002 (Silver Ticket)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs

### Description

Detects Silver Ticket attacks where attackers forge service tickets for specific services without contacting the KDC.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4769
| where Service_Name!="krbtgt" AND Service_Name!="*$"
| stats count, dc(Client_Address) as unique_clients, values(Client_Address) as clients by Account_Name, Service_Name
| where unique_clients > 10 AND count > 50
| eval description="High volume service ticket usage without TGT requests - possible Silver Ticket"
| table Account_Name, Service_Name, count, unique_clients, clients
```

### SPL Query - Missing TGT Pattern

```spl
# Correlation search - Service tickets without corresponding TGTs
index=windows sourcetype="WinEventLog:Security" EventCode=4769
| stats count as tgs_count by Account_Name, _time
| join Account_Name [
  search index=windows sourcetype="WinEventLog:Security" EventCode=4768
  | stats count as tgt_count by Account_Name, _time
]
| where tgs_count > tgt_count * 2
| eval description="Service tickets significantly exceed TGT requests - Silver Ticket indicator"
```

### Notable Event Configuration

```
Title: Silver Ticket Attack Detected - $Account_Name$ / $Service_Name$
Description: Account $Account_Name$ is using service $Service_Name$ with patterns indicating forged service ticket (Silver Ticket).
- Service ticket count: $count$
- Unique clients: $unique_clients$
- Ratio of TGS to TGT requests is abnormal

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1558.002

Recommended Actions:
1. Disable account $Account_Name$
2. Reset password for service account $Service_Name$
3. Investigate all clients in list
4. Review service account configuration
5. Check for lateral movement from listed clients
6. Escalate to Incident Response Team
```

### Response Actions

1. Disable user account
2. Reset service account password
3. Investigate client systems
4. Check for lateral movement
5. Review service account permissions

---

## DET-KRB-004: AS-REP Roasting Detection

### Overview
- **Detection ID**: DET-KRB-004
- **MITRE ATT&CK**: T1558.004 (AS-REP Roasting)
- **Severity**: Medium
- **Data Sources**: Windows Security Event Logs

### Description

Detects AS-REP Roasting attacks targeting accounts with "Do not require Kerberos preauthentication" enabled.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4768
| where Pre_Authentication_Type="0"
| stats count, values(Client_Address) as sources by Account_Name
| where count > 1
| eval description="Multiple AS-REQ without pre-auth - possible AS-REP Roasting"
| table _time, Account_Name, count, sources
```

### SPL Query - Detection of Vulnerable Accounts

```spl
# Detects accounts with pre-auth disabled (vulnerability scan)
index=windows sourcetype="WinEventLog:Security" EventCode=4738
| where UAC_New LIKE "%DONT_REQ_PREAUTH%"
| table _time, TargetUserName, SubjectUserName, ComputerName
| eval description="Account configured to not require pre-authentication - AS-REP Roasting vulnerability"
```

### Notable Event Configuration

```
Title: AS-REP Roasting Attack - $Account_Name$
Description: Multiple AS-REQ requests without pre-authentication for account $Account_Name$. This account may have been targeted for AS-REP Roasting attack.
Request count: $count$
Source IPs: $sources$

Severity: medium
Urgency: high
Security Domain: access
MITRE ATT&CK: T1558.004

Recommended Actions:
1. Enable Kerberos pre-authentication for $Account_Name$
2. Reset password for $Account_Name$ (assume compromised)
3. Investigate source IPs for malicious activity
4. Scan AD for other accounts with pre-auth disabled
5. Implement strong passwords for affected accounts
```

### Preventive Query

```spl
# Find all accounts vulnerable to AS-REP Roasting
| ldapsearch domain=DC=company,DC=com search="(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" attrs=sAMAccountName,userAccountControl
| table sAMAccountName
```

---

## DET-KRB-005: Overpass-the-Hash Detection

### Overview
- **Detection ID**: DET-KRB-005
- **MITRE ATT&CK**: T1550.002 (Pass the Hash), T1558 (Steal or Forge Kerberos Tickets)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs

### Description

Detects Overpass-the-Hash (Pass-the-Key) attacks where NTLM hashes are used to obtain Kerberos tickets.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4768
| where Ticket_Encryption_Type="0x17"
| stats count, values(Client_Address) as sources, dc(Client_Address) as unique_sources by Account_Name
| where unique_sources > 1 AND count > 5
| eval description="Multiple RC4 TGT requests from different sources - possible Overpass-the-Hash"
| table _time, Account_Name, count, unique_sources, sources
```

### SPL Query - Correlation with Logon Events

```spl
# Detect RC4 TGT followed by network logon
index=windows sourcetype="WinEventLog:Security"
    (EventCode=4768 Ticket_Encryption_Type="0x17") OR (EventCode=4624 Logon_Type=3)
| transaction Account_Name maxspan=5m
| where eventcount > 1
| search EventCode=4768 AND EventCode=4624
| table _time, Account_Name, Client_Address, IpAddress, ComputerName
| eval description="RC4 TGT followed by network logon - Overpass-the-Hash indicator"
```

### Notable Event Configuration

```
Title: Overpass-the-Hash Attack Detected - $Account_Name$
Description: Account $Account_Name$ shows indicators of Overpass-the-Hash attack:
- Multiple RC4-encrypted TGT requests
- Requests from different source IPs: $sources$
- Followed by network logons

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1550.002, T1558

Recommended Actions:
1. Disable account $Account_Name$ immediately
2. Investigate all source IPs for compromise
3. Reset account password
4. Review all recent logon activity
5. Check for lateral movement
6. Implement AES-only Kerberos encryption
```

---

## DET-KRB-006: Skeleton Key Attack Detection

### Overview
- **Detection ID**: DET-KRB-006
- **MITRE ATT&CK**: T1556 (Modify Authentication Process)
- **Severity**: Critical
- **Data Sources**: Windows Security Event Logs, Sysmon

### Description

Detects Skeleton Key malware that patches LSASS to accept a master password for any account.

### SPL Query - LSASS Access

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| where TargetImage="C:\\Windows\\System32\\lsass.exe"
| where GrantedAccess="0x1F3FFF" OR GrantedAccess="0x1FFFFF"
| search NOT [ | inputlookup authorized_lsass_access.csv | fields SourceImage ]
| table _time, ComputerName, SourceImage, SourceUser, GrantedAccess, CallTrace
| eval description="Suspicious LSASS access - possible Skeleton Key or credential dumping"
```

### SPL Query - Skeleton Key Specific Indicators

```spl
index=windows sourcetype="WinEventLog:System" EventCode=7045
| where Service_Name="msuta" OR Service_Name="msupdater"
| eval description="Skeleton Key malware service installation detected"
```

### Notable Event Configuration

```
Title: CRITICAL - Skeleton Key Attack Detected on $ComputerName$
Description: Suspicious access to LSASS detected on $ComputerName$ by process $SourceImage$ (user: $SourceUser$). This may indicate Skeleton Key malware installation.

Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1556

Recommended Actions:
1. IMMEDIATELY isolate $ComputerName$ from network
2. DO NOT reboot (may clear malware from memory)
3. Capture memory dump for forensic analysis
4. Reset ALL domain passwords if confirmed
5. Investigate for domain controller compromise
6. Full incident response procedure
7. Escalate to IR Team and CISO immediately
```

---

## Summary - Kerberos Attack Detections

| Detection ID | Attack Type | Severity | Complexity | Priority |
|--------------|-------------|----------|------------|----------|
| DET-KRB-001 | Kerberoasting | High | Medium | 1 |
| DET-KRB-002 | Golden Ticket | Critical | High | 1 |
| DET-KRB-003 | Silver Ticket | High | High | 2 |
| DET-KRB-004 | AS-REP Roasting | Medium | Low | 3 |
| DET-KRB-005 | Overpass-the-Hash | High | Medium | 2 |
| DET-KRB-006 | Skeleton Key | Critical | Low | 1 |

## Detection Correlation

Many Kerberos attacks occur in sequence. Use correlation searches:

```spl
# Multi-stage Kerberos attack correlation
index=windows sourcetype="WinEventLog:Security" (EventCode=4768 OR EventCode=4769 OR EventCode=4770)
| transaction Account_Name maxspan=30m
| where eventcount > 20
| stats count by Account_Name, EventCode
| eval description="High-volume Kerberos activity - possible attack chain"
```

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
