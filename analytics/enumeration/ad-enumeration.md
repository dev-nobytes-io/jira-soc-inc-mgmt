# Active Directory & Network Enumeration Detections

## Overview

Detections for reconnaissance and enumeration activities that precede attacks. These detections identify attackers mapping the environment before lateral movement or privilege escalation.

---

## DET-ENUM-001: LDAP Enumeration Detection

### Overview
- **Detection ID**: DET-ENUM-001
- **MITRE ATT&CK**: T1087.002 (Domain Account Discovery), T1069.002 (Domain Groups)
- **Severity**: Medium
- **Data Sources**: Windows Security Event Logs, Network Traffic

### Description

Detects LDAP queries used to enumerate Active Directory objects, groups, and users. Attackers use tools like BloodHound, ADExplorer, and PowerView for reconnaissance.

### SPL Query - Excessive LDAP Queries

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=1644
| stats count, dc(Search_Filter) as unique_queries, values(Search_Filter) as queries by SubjectUserName, IpAddress
| where count > 100 OR unique_queries > 20
| eval description="Excessive LDAP enumeration detected"
| table _time, SubjectUserName, IpAddress, count, unique_queries, queries
| sort - count
```

### SPL Query - Sensitive LDAP Queries

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=1644
| eval is_sensitive=if(
    match(Search_Filter, "(?i)(adminCount=1|memberOf.*admin|servicePrincipalName|userAccountControl|pwdLastSet|badPwdCount)"),
    "true", "false"
)
| where is_sensitive="true"
| stats count, values(Search_Filter) as sensitive_queries by SubjectUserName, IpAddress
| eval description="Sensitive AD attribute enumeration"
| table _time, SubjectUserName, IpAddress, count, sensitive_queries
```

### SPL Query - BloodHound Detection

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(sharphound|bloodhound|invoke-bloodhound|azurehound)")
    OR match(Image, "(?i)(sharphound|azurehound)")
| table _time, User, ComputerName, Image, CommandLine, ParentImage
| eval description="BloodHound enumeration tool detected"
```

### SPL Query - Network-Based LDAP Enumeration

```spl
index=corelight sourcetype=corelight_conn
| where id.resp_p=389 OR id.resp_p=636 OR id.resp_p=3268 OR id.resp_p=3269
| stats count, sum(orig_bytes) as bytes_sent, sum(resp_bytes) as bytes_received by id.orig_h
| eval MB_received=round(bytes_received/1024/1024,2)
| where count > 1000 OR MB_received > 10
| lookup asset_info.csv ip as id.orig_h OUTPUT hostname, asset_type
| where asset_type!="domain_controller"
| eval description="High volume LDAP queries - possible enumeration"
| table _time, id.orig_h, hostname, count, MB_received
```

### Notable Event Configuration

```
Title: Active Directory Enumeration Detected - $SubjectUserName$ from $IpAddress$
Description: Excessive LDAP queries detected indicating AD enumeration:

User: $SubjectUserName$
Source: $IpAddress$
Query Count: $count$
Unique Queries: $unique_queries$

This activity is consistent with reconnaissance tools like:
- BloodHound / SharpHound
- PowerView
- ADExplorer
- ldapsearch abuse

Severity: medium
Urgency: high
Security Domain: access
MITRE ATT&CK: T1087.002, T1069.002

Recommended Actions:
1. Investigate $SubjectUserName$ account for compromise
2. Review query patterns for attack path enumeration
3. Check for follow-on attacks (Kerberoasting, privilege escalation)
4. Identify tools used (check process execution logs)
5. If unauthorized, disable account and investigate
6. Review all recent activity by this account
7. Check for data exfiltration (BloodHound JSON files)
```

### Detection Enhancement - LDAP Query Pattern Analysis

```spl
index=windows EventCode=1644
| rex field=Search_Filter "(?<attribute>\w+)="
| stats count by attribute, SubjectUserName
| where count > 50
| eval attack_pattern=case(
    attribute="servicePrincipalName", "Kerberoasting Preparation",
    attribute="adminCount", "Admin Account Enumeration",
    attribute="memberOf", "Group Membership Mapping",
    attribute="userAccountControl", "Account Status Enumeration",
    1=1, "General Enumeration"
)
| table SubjectUserName, attribute, count, attack_pattern
```

### Response Actions

1. Identify enumeration tool used
2. Check for data exfiltration (BloodHound JSON exports)
3. Review enumerated objects for attack path
4. Monitor for follow-on attacks
5. Disable compromised account if confirmed

---

## DET-ENUM-002: Network Share Enumeration

### Overview
- **Detection ID**: DET-ENUM-002
- **MITRE ATT&CK**: T1135 (Network Share Discovery)
- **Severity**: Medium
- **Data Sources**: Windows Security Logs, Sysmon, Network Traffic

### Description

Detects enumeration of network shares across multiple systems, often used to map file servers and identify sensitive data locations.

### SPL Query - Excessive Share Access Attempts

```spl
index=windows EventCode=5140
| stats dc(Share_Name) as unique_shares, dc(ComputerName) as unique_hosts,
    values(Share_Name) as shares, values(ComputerName) as hosts
    by SubjectUserName, IpAddress
| where unique_hosts > 10 OR unique_shares > 20
| eval description="Network share enumeration detected"
| table _time, SubjectUserName, IpAddress, unique_hosts, unique_shares, hosts, shares
```

### SPL Query - net view Command Detection

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(net\s+view|net\s+share|net\s+use)")
| stats count, values(ComputerName) as systems by User, CommandLine
| where count > 5
| eval description="Net view/share enumeration commands"
| table _time, User, CommandLine, count, systems
```

### SPL Query - SMB Tree Connect Enumeration

```spl
index=corelight sourcetype=corelight_smb_mapping
| stats dc(path) as unique_shares, values(path) as shares by id.orig_h
| where unique_shares > 15
| eval description="SMB share enumeration from network traffic"
| table _time, id.orig_h, unique_shares, shares
```

### Notable Event Configuration

```
Title: Network Share Enumeration - $SubjectUserName$ scanned $unique_hosts$ systems
Description: Network share enumeration activity detected:

User: $SubjectUserName$
Source IP: $IpAddress$
Systems Scanned: $unique_hosts$
Shares Accessed: $unique_shares$

Systems: $hosts$
Shares: $shares$

This behavior indicates reconnaissance for:
- Sensitive data location
- File server mapping
- Pre-ransomware enumeration
- Data exfiltration targets

Severity: medium
Urgency: high
Security Domain: network
MITRE ATT&CK: T1135

Recommended Actions:
1. Verify if $SubjectUserName$ requires access to these shares
2. Check for legitimate backup/migration activity
3. If unauthorized, disable account immediately
4. Review shares for sensitive data
5. Check for follow-on data access or exfiltration
6. Investigate for ransomware indicators
7. Review file access logs on enumerated shares
```

### Response Actions

1. Verify business justification
2. Check for data staging or exfiltration
3. Monitor file access on enumerated shares
4. Disable account if unauthorized
5. Alert data owners of targeted shares

---

## DET-ENUM-003: Domain Trust Enumeration

### Overview
- **Detection ID**: DET-ENUM-003
- **MITRE ATT&CK**: T1482 (Domain Trust Discovery)
- **Severity**: Medium
- **Data Sources**: Windows PowerShell Logs, Sysmon

### Description

Detects enumeration of domain trust relationships, often performed by attackers to identify paths for lateral movement across domains.

### SPL Query - PowerShell Trust Enumeration

```spl
index=windows (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
    OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
| where match(ScriptBlockText, "(?i)(Get-ADTrust|Get-DomainTrust|nltest.*trust|Get-NetDomainTrust)")
    OR match(CommandLine, "(?i)(Get-ADTrust|Get-DomainTrust|nltest.*\/domain_trusts)")
| table _time, User, ComputerName, CommandLine, ScriptBlockText
| eval description="Domain trust enumeration detected"
```

### SPL Query - nltest Command Detection

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where Image="*\\nltest.exe"
| where match(CommandLine, "(?i)(\/domain_trusts|\/all_trusts|\/trusted_domains)")
| stats count by User, ComputerName, CommandLine
| eval description="nltest.exe used for trust enumeration"
```

### Notable Event Configuration

```
Title: Domain Trust Enumeration - $User$ on $ComputerName$
Description: Domain trust relationship enumeration detected:

User: $User$
System: $ComputerName$
Command: $CommandLine$

This activity maps trust relationships for:
- Cross-domain lateral movement
- Forest compromise planning
- Attack path identification

Common in APT reconnaissance phase.

Severity: medium
Urgency: high
Security Domain: access
MITRE ATT&CK: T1482

Recommended Actions:
1. Investigate $User$ account for compromise
2. Review trust relationships for security
3. Check for cross-domain authentication attempts
4. Monitor for lateral movement to trusted domains
5. Verify business justification for enumeration
6. Check for other reconnaissance activities
```

---

## DET-ENUM-004: Service Principal Name (SPN) Enumeration

### Overview
- **Detection ID**: DET-ENUM-004
- **MITRE ATT&CK**: T1558.003 (Kerberoasting)
- **Severity**: Medium
- **Data Sources**: Windows PowerShell Logs, Sysmon

### Description

Detects enumeration of Service Principal Names (SPNs) which precedes Kerberoasting attacks.

### SPL Query - SPN Enumeration Tools

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(Get-NetUser.*-SPN|Get-ADUser.*servicePrincipalName|setspn|GetUserSPNs)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="SPN enumeration - Kerberoasting preparation"
```

### SPL Query - setspn.exe Usage

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where Image="*\\setspn.exe"
| where match(CommandLine, "(?i)(-Q|-T|-L)")
| stats count, values(CommandLine) as commands by User, ComputerName
| eval description="setspn.exe used for SPN discovery"
```

### SPL Query - LDAP SPN Queries

```spl
index=windows EventCode=1644
| where match(Search_Filter, "(?i)servicePrincipalName")
| stats count, values(Search_Filter) as queries by SubjectUserName, IpAddress
| where count > 10
| eval description="LDAP queries for SPNs - Kerberoasting prep"
```

### Notable Event Configuration

```
Title: SPN Enumeration Detected - Kerberoasting Preparation - $User$
Description: Service Principal Name enumeration detected:

User: $User$
System: $ComputerName$
Method: $description$

This is the FIRST STEP in Kerberoasting attacks:
1. Enumerate SPNs (current activity)
2. Request service tickets (next step)
3. Offline password cracking

Expect Kerberoasting attack to follow.

Severity: medium
Urgency: high
Security Domain: access
MITRE ATT&CK: T1558.003

Recommended Actions:
1. Enable monitoring for Kerberoasting (DET-KRB-001)
2. Verify SPN account password strength
3. Investigate $User$ for compromise
4. Consider implementing gMSA for service accounts
5. Monitor for follow-on TGS-REQ requests
6. Alert on any Kerberos ticket requests from this user
```

---

## DET-ENUM-005: Admin Account Discovery

### Overview
- **Detection ID**: DET-ENUM-005
- **MITRE ATT&CK**: T1087.002 (Domain Account Discovery)
- **Severity**: Medium
- **Data Sources**: PowerShell Logs, Sysmon, Windows Security

### Description

Detects enumeration of administrative accounts and privileged users.

### SPL Query - Admin Group Enumeration

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(net\s+group.*admin|net\s+localgroup.*admin|Get-ADGroupMember.*admin)")
| stats count, values(CommandLine) as commands by User, ComputerName
| eval description="Administrative group enumeration"
```

### SPL Query - PowerView Admin Discovery

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(Get-NetGroupMember.*admin|Get-DomainGroupMember|Find-DomainUserLocation|Get-DomainAdmin)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="PowerView admin enumeration detected"
```

### SPL Query - adminCount Attribute Queries

```spl
index=windows EventCode=1644
| where match(Search_Filter, "(?i)adminCount=1")
| stats count by SubjectUserName, IpAddress
| where count > 5
| eval description="LDAP queries for protected admin accounts (adminCount=1)"
```

### Notable Event Configuration

```
Title: Admin Account Enumeration - $User$
Description: Administrative account discovery activity:

User: $User$
System: $ComputerName$
Commands: $commands$

Attacker is identifying privileged accounts for targeting.

Severity: medium
Urgency: high
Security Domain: access
MITRE ATT&CK: T1087.002

Recommended Actions:
1. Investigate $User$ for compromise
2. Alert on any access attempts to enumerated admin accounts
3. Review admin account security posture
4. Monitor for privilege escalation attempts
5. Check for credential dumping tools
6. Enhanced monitoring for enumerated accounts
```

---

## DET-ENUM-006: Local Admin Enumeration Across Network

### Overview
- **Detection ID**: DET-ENUM-006
- **MITRE ATT&CK**: T1087.001 (Local Account Discovery)
- **Severity**: High
- **Data Sources**: Windows Security Logs, Network Traffic

### Description

Detects enumeration of local administrators across multiple systems, often used to identify systems where compromised credentials have admin rights.

### SPL Query - Remote SAM Enumeration

```spl
index=windows EventCode=4799
| stats count, dc(ComputerName) as unique_systems, values(ComputerName) as systems by SubjectUserName, IpAddress
| where unique_systems > 10
| eval description="Local admin group enumeration across multiple systems"
| table _time, SubjectUserName, IpAddress, unique_systems, systems
```

### SPL Query - net localgroup Remote Execution

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)net\s+localgroup\s+administrators")
| stats count, dc(ComputerName) as systems_scanned by User
| where systems_scanned > 5
| eval description="Local admin enumeration via net localgroup"
```

### SPL Query - Find-LocalAdminAccess (PowerView)

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(Find-LocalAdminAccess|Invoke-EnumerateLocalAdmin|Test-AdminAccess)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="PowerView local admin access enumeration"
```

### Notable Event Configuration

```
Title: Local Admin Enumeration Across Network - $SubjectUserName$
Description: Local administrator enumeration across $unique_systems$ systems:

User: $SubjectUserName$
Source: $IpAddress$
Systems Scanned: $unique_systems$
Target Systems: $systems$

Attacker is mapping where they have admin rights for lateral movement.

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1087.001

Recommended Actions:
1. IMMEDIATE - Disable $SubjectUserName$ account
2. Check for lateral movement to enumerated systems
3. Review local admin group membership across estate
4. Implement LAPS if not already deployed
5. Remove unnecessary local admin rights
6. Check for follow-on lateral movement
7. Full investigation of compromised account
```

---

## DET-ENUM-007: Port and Service Discovery

### Overview
- **Detection ID**: DET-ENUM-007
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Severity**: Medium
- **Data Sources**: Corelight/Zeek, Windows Event Logs

### Description

Detects internal network scanning to discover running services and open ports.

### SPL Query - Internal Port Scan (Corelight)

```spl
index=corelight sourcetype=corelight_conn
| where local_orig="T" AND local_resp="T"
| stats dc(id.resp_p) as unique_ports,
    dc(id.resp_h) as unique_hosts,
    values(id.resp_p) as ports_scanned
    by id.orig_h
| where unique_ports > 20 OR unique_hosts > 50
| lookup asset_info.csv ip as id.orig_h OUTPUT hostname, asset_type
| where asset_type!="vulnerability_scanner"
| eval description="Internal port scanning detected"
| table _time, id.orig_h, hostname, unique_hosts, unique_ports, ports_scanned
```

### SPL Query - Nmap Detection

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(Image, "(?i)nmap") OR match(CommandLine, "(?i)nmap")
| table _time, User, ComputerName, CommandLine, ParentImage
| eval description="Nmap scanning tool detected"
```

### SPL Query - PowerShell Port Scan

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(Test-NetConnection.*-Port|PortScan|Invoke-Portscan)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="PowerShell port scanning detected"
```

### Notable Event Configuration

```
Title: Network Port Scanning - $id.orig_h$ scanned $unique_hosts$ hosts
Description: Internal port scanning detected:

Source: $id.orig_h$ ($hostname$)
Hosts Scanned: $unique_hosts$
Ports Scanned: $unique_ports$
Ports: $ports_scanned$

Network reconnaissance activity indicating:
- Pre-attack mapping
- Vulnerability identification
- Service discovery

Severity: medium
Urgency: high
Security Domain: network
MITRE ATT&CK: T1046

Recommended Actions:
1. Identify user/process performing scan
2. Verify if authorized vulnerability scanning
3. If unauthorized, isolate $id.orig_h$
4. Review scan targets for sensitive systems
5. Check for follow-on exploitation attempts
6. Monitor scanned systems for compromise
```

---

## DET-ENUM-008: Password Policy Discovery

### Overview
- **Detection ID**: DET-ENUM-008
- **MITRE ATT&CK**: T1201 (Password Policy Discovery)
- **Severity**: Low
- **Data Sources**: Windows Event Logs, Sysmon

### Description

Detects attempts to enumerate domain password policies, often done before password spray attacks.

### SPL Query - Password Policy Queries

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(net\s+accounts|Get-ADDefaultDomainPasswordPolicy|Get-DomainPolicy)")
| stats count by User, ComputerName, CommandLine
| eval description="Password policy enumeration detected"
```

### SPL Query - LDAP Password Policy Queries

```spl
index=windows EventCode=1644
| where match(Search_Filter, "(?i)(maxPwdAge|minPwdAge|minPwdLength|lockoutThreshold|pwdHistoryLength)")
| stats count, values(Search_Filter) as queries by SubjectUserName
| where count > 3
| eval description="LDAP queries for password policy attributes"
```

### Notable Event Configuration

```
Title: Password Policy Discovery - $User$
Description: Password policy enumeration detected:

User: $User$
System: $ComputerName$
Command: $CommandLine$

This often precedes password spray attacks.

Severity: low
Urgency: medium
Security Domain: access
MITRE ATT&CK: T1201

Recommended Actions:
1. Monitor for password spray attempts (Event 4625)
2. Check account lockout policy effectiveness
3. Investigate $User$ for compromise
4. Review recent authentication failures
5. Enable password spray detection (DET-AUTH-003)
```

---

## Summary - Enumeration Detections

| Detection ID | Enumeration Type | Technique | Severity | Tools Detected |
|--------------|------------------|-----------|----------|----------------|
| DET-ENUM-001 | LDAP/AD Enumeration | T1087.002 | Medium | BloodHound, PowerView, ADExplorer |
| DET-ENUM-002 | Network Shares | T1135 | Medium | net view, SMB enumeration |
| DET-ENUM-003 | Domain Trusts | T1482 | Medium | nltest, PowerView |
| DET-ENUM-004 | SPN Discovery | T1558.003 | Medium | setspn, GetUserSPNs |
| DET-ENUM-005 | Admin Accounts | T1087.002 | Medium | PowerView, net group |
| DET-ENUM-006 | Local Admins | T1087.001 | High | Find-LocalAdminAccess |
| DET-ENUM-007 | Port/Service Scan | T1046 | Medium | Nmap, PowerShell |
| DET-ENUM-008 | Password Policy | T1201 | Low | net accounts, LDAP |

## Correlation - Enumeration Attack Chain

Enumeration activities often occur in sequence. Create correlation searches to detect attack chains:

```spl
# Multi-stage enumeration correlation
index=windows (EventCode=1 OR EventCode=1644 OR EventCode=4104)
| eval enum_activity=case(
    match(Search_Filter, "(?i)servicePrincipalName"), "SPN_ENUM",
    match(ScriptBlockText, "(?i)Get-DomainTrust"), "TRUST_ENUM",
    match(CommandLine, "(?i)bloodhound"), "AD_ENUM",
    match(CommandLine, "(?i)net\s+view"), "SHARE_ENUM",
    1=1, null()
)
| where isnotnull(enum_activity)
| stats count, dc(enum_activity) as enum_types, values(enum_activity) as activities by User, ComputerName
| where enum_types >= 3
| eval description="Multi-stage enumeration attack chain detected"
```

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
**Total Enumeration Detections**: 8
