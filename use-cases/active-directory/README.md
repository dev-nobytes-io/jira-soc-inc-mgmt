# Active Directory Security Use Cases

## Overview

This directory contains detailed use cases for Active Directory security threats including Kerberos attacks, DCSync, Golden/Silver Tickets, and AD persistence mechanisms.

## Use Case Index

### Critical Priority (P1)

1. **[UC-AD-001: Golden Ticket Attack](#uc-ad-001-golden-ticket-attack)**
   - Full domain compromise via krbtgt hash
   - Severity: Critical
   - MITRE: T1558.001

2. **[UC-AD-002: DCSync Attack](#uc-ad-002-dcsync-attack)**
   - Credential dumping via directory replication
   - Severity: Critical
   - MITRE: T1003.006

3. **[UC-AD-003: AdminSDHolder Persistence](#uc-ad-003-adminsdholder-persistence)**
   - Persistent admin rights via AdminSDHolder
   - Severity: Critical
   - MITRE: T1484

### High Priority (P2)

4. **[UC-AD-004: Kerberoasting Attack](#uc-ad-004-kerberoasting-attack)**
   - Service account password cracking
   - Severity: High
   - MITRE: T1558.003

5. **[UC-AD-005: Silver Ticket Attack](#uc-ad-005-silver-ticket-attack)**
   - Forged service tickets
   - Severity: High
   - MITRE: T1558.002

6. **[UC-AD-006: AS-REP Roasting](#uc-ad-006-as-rep-roasting)**
   - Attack on accounts without pre-auth
   - Severity: Medium
   - MITRE: T1558.004

7. **[UC-AD-007: NTDS.dit Theft](#uc-ad-007-ntdsdit-theft)**
   - Active Directory database theft
   - Severity: Critical
   - MITRE: T1003.003

### Medium Priority (P3)

8. **[UC-AD-008: Group Policy Object (GPO) Abuse](#uc-ad-008-gpo-abuse)**
   - Malicious GPO for persistence/lateral movement
   - Severity: High
   - MITRE: T1484.001

9. **[UC-AD-009: DCShadow Attack](#uc-ad-009-dcshadow-attack)**
   - Rogue domain controller creation
   - Severity: Critical
   - MITRE: T1207

10. **[UC-AD-010: Skeleton Key Malware](#uc-ad-010-skeleton-key-malware)**
    - Master password backdoor on DC
    - Severity: Critical
    - MITRE: T1556.001

---

## UC-AD-001: Golden Ticket Attack

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AD-001 |
| **Name** | Golden Ticket Attack - Full Domain Compromise |
| **Category** | Active Directory, Credential Access, Persistence |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1558.001 (Golden Ticket) |
| **Detection IDs** | DET-KRB-002 |

### Description

A Golden Ticket attack involves forging Kerberos Ticket Granting Tickets (TGT) using the krbtgt account hash. This represents **FULL DOMAIN COMPROMISE** as attackers can impersonate any user, including Domain Admins, and maintain access even after password changes.

### Attack Scenario

**Prerequisites** (How krbtgt hash is obtained):
1. Domain Controller compromise
2. DCSync attack (DET-AD-002)
3. NTDS.dit database theft
4. Volume Shadow Copy access on DC
5. Mimikatz DCSync

**Attack Execution**:
```powershell
# Using Mimikatz to create Golden Ticket
mimikatz # kerberos::golden /domain:company.com /sid:S-1-5-21-... /rc4:[krbtgt_hash] /user:Administrator /id:500 /ptt

# Result: TGT valid for 10 years with admin rights
```

**Attack Characteristics**:
- Forged tickets have abnormal lifetime (default: 10 hours, attack: often years)
- May use RC4 encryption (downgrade from AES)
- Can impersonate any user including non-existent accounts
- Persists through password changes (except krbtgt)
- Undetectable by standard authentication logs

### Detection Logic

**Primary Detection Indicators**:

1. **Abnormal Ticket Lifetime**:
```spl
EventCode=4768 (TGT Request)
WHERE ticket_lifetime > 10 hours
AND Account_Name != "computer$"
```

2. **Encryption Downgrade**:
```spl
EventCode=4768
WHERE Ticket_Encryption_Type = 0x17 (RC4)
AND Account expected to use AES
```

3. **Ticket Option Anomalies**:
```spl
EventCode=4769 (Service Ticket Request)
WHERE TGT used has abnormal attributes
```

**Key Indicators**:
- Tickets with lifetimes > 10 hours
- RC4 encryption for modern accounts
- TGT requests from unusual sources
- Authentication without corresponding logon

**Data Sources**:
- Windows Security Event Logs (4768, 4769, 4770)
- Domain Controller Security logs
- Network traffic analysis

### Response Procedure

**CRITICAL INCIDENT - Domain Compromise Response**

**Phase 1: IMMEDIATE Actions (0-30 minutes)**

**DO NOT take remediation actions before evidence preservation!**

1. **Activate Incident Response Team**:
   - Page IR Team Lead
   - Notify CISO immediately
   - Contact Legal/Compliance
   - Activate war room

2. **Evidence Preservation** (HIGHEST PRIORITY):
   ```powershell
   # Capture memory from ALL domain controllers
   # DO NOT reboot DCs
   winpmem_v3.3.rc3.exe DC01-memory.raw

   # Export AD database
   ntdsutil "activate instance ntds" "ifm" "create full c:\temp\IFM" quit quit

   # Preserve ALL Kerberos logs
   wevtutil epl Security C:\Evidence\Security-DC01.evtx
   wevtutil epl System C:\Evidence\System-DC01.evtx
   ```

3. **Isolate Known Compromised Systems**:
   - Identify and network-isolate systems with Golden Ticket indicators
   - DO NOT isolate Domain Controllers (causes outage)
   - Document all actions taken

4. **Communication**:
   - Brief executive team (CISO, CEO)
   - Notify legal counsel
   - Prepare regulatory notification if required
   - External IR firm engagement decision

**Phase 2: Investigation (1-8 hours)**

1. **Determine krbtgt Compromise Method**:
   - Review DC access logs
   - Check for DCSync (Event 4662 with specific GUIDs)
   - Check for NTDS.dit access
   - Review VSS access logs
   - Examine DC for Mimikatz or credential dumping

2. **Scope Assessment**:
   ```powershell
   # Find all Golden Ticket usage
   Get-WinEvent -FilterHashtable @{Logname='Security';ID=4768} |
     Where-Object {$_.Properties[5].Value -gt 600} |  # Lifetime > 10 hours
     Select TimeCreated, @{n='Account';e={$_.Properties[0].Value}}
   ```

3. **Timeline Analysis**:
   - When was krbtgt compromised?
   - When were Golden Tickets created?
   - What systems accessed?
   - What data exfiltrated?
   - What persistence mechanisms deployed?

4. **Impact Assessment**:
   - Systems accessed with Golden Tickets
   - Data accessed or stolen
   - Additional backdoors installed
   - Other domains compromised (trusts)

**Phase 3: Containment (8-24 hours)**

**Plan krbtgt Password Reset** (requires careful coordination):

```powershell
# Reference: https://github.com/microsoft/New-KrbtgtKeys.ps1

# Prerequisites:
# - All DCs online and replicating
# - Change control approval
# - Maintenance window scheduled
# - Communications plan

# Reset 1 (invalidates current tickets)
./New-KrbtgtKeys.ps1 -Mode Reset -DomainController DC01

# Wait 10 hours (max ticket lifetime)
# Monitor for issues

# Reset 2 (removes ability to create new tickets with old hash)
./New-KrbtgtKeys.ps1 -Mode Reset -DomainController DC01
```

**CRITICAL CONSIDERATIONS**:
- Requires 2 resets, 10 hours apart
- All legitimate Kerberos tickets invalidated
- Applications may break
- Users may need to re-authenticate
- Plan for 24+ hour operation

**Phase 4: Eradication**

1. **Remove All Attacker Access**:
   - Krbtgt password reset (completed in Containment)
   - Remove backdoor accounts
   - Remove malicious GPOs
   - Remove scheduled tasks/services
   - Remove registry persistence
   - Scan for Skeleton Key malware

2. **Reset Additional Passwords**:
   ```powershell
   # Reset ALL privileged account passwords
   Get-ADUser -Filter {AdminCount -eq 1} | Set-ADAccountPassword

   # Reset all service account passwords
   # (requires service updates)
   ```

3. **Review and Harden**:
   - Remove excessive permissions
   - Implement tiering model
   - Deploy Protected Users group
   - Enable advanced auditing

**Phase 5: Recovery**

1. **Gradual Service Restoration**:
   - Monitor for issues after krbtgt reset
   - Re-enable affected services
   - Verify authentication working
   - User support for re-authentication

2. **Enhanced Monitoring**:
   ```spl
   # Monitor for reinfection indicators
   index=windows EventCode IN (4768,4769)
   | where ticket_lifetime > 10 OR Ticket_Encryption_Type="0x17"
   | stats count by Account_Name, Client_Address
   ```

3. **Validation**:
   - Confirm no Golden Tickets remain active
   - Verify all backdoors removed
   - Test authentication across environment

**Phase 6: Post-Incident**

1. **Root Cause Analysis**:
   - How was DC compromised?
   - What vulnerabilities exploited?
   - Security control failures?
   - Timeline of compromise

2. **Lessons Learned**:
   - Detection gaps identified
   - Response effectiveness
   - Communication issues
   - Recovery challenges

3. **Remediation**:
   - Implement technical controls:
     * Privileged Access Workstations (PAW)
     * Tier 0 asset protection
     * Enhanced DC monitoring
     * Just-in-time admin access
   - Process improvements:
     * Incident response plan updates
     * Faster evidence collection
     * Pre-approved krbtgt reset procedure
   - Detection enhancements:
     * Real-time Golden Ticket detection
     * DC access monitoring
     * Credential dumping detection

### False Positives

**Extremely Rare** - Golden Ticket indicators should be investigated as malicious unless conclusively proven otherwise.

Possible benign scenarios:
- Lab/test environment with intentionally long tickets
- Time synchronization issues (rare)
- Legacy applications with old Kerberos implementations

**Investigation Required**: Every detection requires full investigation.

### Escalation Criteria

**AUTOMATIC CRITICAL ESCALATION** - Always escalate:
- Immediate notification to CISO
- IR Team Lead activation
- Executive briefing within 1 hour
- Legal/compliance notification
- Consider external IR firm
- Law enforcement (if APT suspected)

### JIRA Workflow

1. **Auto-Create**: JIRA incident (Severity: Critical, Urgency: Critical)
2. **Status**: New → War Room Activated
3. **Assignment**: Incident Response Team Lead
4. **SLA**: 15-minute acknowledgment, continuous response until resolved
5. **Tags**: domain-compromise, golden-ticket, critical-incident

### Metrics

- Time to detect Golden Ticket usage
- Time to activate IR team
- Time to evidence preservation
- krbtgt reset execution time
- Total recovery time
- Systems affected count
- Data exfiltration volume

### Prevention

**Technical Controls**:
- Privileged Access Workstations (PAW) for DC access
- Tier 0 asset segmentation
- Just-in-time admin access
- Credential Guard on DCs
- Advanced threat protection
- Enhanced auditing
- Network segmentation

**Detection Controls**:
- Real-time Kerberos monitoring
- DC access monitoring
- Credential dumping detection
- Abnormal authentication detection
- SIEM correlation rules

**Process Controls**:
- Pre-approved krbtgt reset procedure
- Regular DC security audits
- Incident response drills
- Evidence collection procedures
- External IR retainer

### Related Use Cases

- UC-AD-002: DCSync Attack (how krbtgt often obtained)
- UC-AD-007: NTDS.dit Theft (alternative krbtgt compromise)
- UC-AD-009: DCShadow Attack (similar domain-level attack)
- UC-AD-010: Skeleton Key Malware (alternative DC compromise)

### Playbooks

- [Golden Ticket Response](../../playbooks/active-directory/golden-ticket.md)
- [Domain Compromise Response](../../playbooks/active-directory/domain-compromise.md)
- [krbtgt Password Reset Procedure](../../playbooks/active-directory/krbtgt-reset.md)

### References

- MITRE ATT&CK T1558.001: https://attack.mitre.org/techniques/T1558/001/
- Microsoft krbtgt Reset Script: https://github.com/microsoft/New-KrbtgtKeys.ps1
- NSA Detecting Kerberos Attacks: https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF
- NIST SP 800-53: SC-12 (Cryptographic Key Management)

---

## UC-AD-002: DCSync Attack

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AD-002 |
| **Name** | DCSync Attack - Credential Dumping via Replication |
| **Category** | Active Directory, Credential Access |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1003.006 (DCSync) |
| **Detection IDs** | DET-AD-007, DET-AD-008 |

### Description

DCSync is an attack technique that abuses Directory Replication Service (DRS) to request password data from domain controllers, including NTLM hashes and Kerberos keys. Does not require code execution on DC.

### Attack Scenario

**Prerequisites**:
1. Compromised account with replication permissions:
   - Domain Admins
   - Enterprise Admins
   - Account with "Replicating Directory Changes" permissions

**Attack Execution**:
```powershell
# Using Mimikatz
mimikatz # lsadump::dcsync /domain:company.com /user:krbtgt

# Using PowerSploit
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:company.com /all"'

# Using Impacket secretsdump.py
secretsdump.py company.com/admin@dc01.company.com
```

**What Attacker Obtains**:
- NTLM hashes for all accounts
- Kerberos keys
- krbtgt hash (for Golden Tickets)
- Password history
- Supplemental credentials

### Detection Logic

**Primary Detection - Event 4662**:
```spl
index=windows EventCode=4662
| where ObjectType="DS-Replication-Get-Changes" OR ObjectType="DS-Replication-Get-Changes-All"
| eval is_dc=if(match(SubjectUserName, "(?i).*\$$"), "true", "false")
| where is_dc="false"
| table _time, SubjectUserName, IpAddress, ObjectName, OperationType
| eval description="Non-DC account performing directory replication - DCSync attack"
```

**Enhanced Detection - GUID-Based**:
```spl
index=windows EventCode=4662
| where match(Properties, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")  # DS-Replication-Get-Changes
    OR match(Properties, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")  # DS-Replication-Get-Changes-All
| eval is_computer=if(like(SubjectUserName, "%$"), "true", "false")
| where is_computer="false"
| stats count by SubjectUserName, IpAddress, ObjectServer
| eval description="DCSync attack detected via replication GUID"
```

**Network-Based Detection**:
```spl
index=corelight sourcetype=corelight_dce_rpc
| where endpoint="drsuapi"
| where operation="DRSGetNCChanges"
| lookup asset_info.csv ip as id.orig_h OUTPUT asset_type
| where asset_type!="domain_controller"
| eval description="DRS replication from non-DC - DCSync attack"
```

### Response Procedure

**Phase 1: Immediate Containment (0-15 minutes)**

1. **Disable Compromised Account**:
   ```powershell
   Disable-ADAccount -Identity [compromised_account]
   ```

2. **Revoke Active Sessions**:
   ```powershell
   # Force logoff all sessions
   Get-ADUser [compromised_account] | Revoke-AzureADUserAllRefreshToken
   ```

3. **Block Source IP** (if not DC):
   ```powershell
   # Block at firewall
   New-NetFirewallRule -DisplayName "Block DCSync Source" -Direction Outbound -RemoteAddress [source_ip] -Action Block
   ```

**Phase 2: Investigation (15-60 minutes)**

1. **Identify What Was Dumped**:
   ```spl
   index=windows EventCode=4662 SubjectUserName="[compromised_account]"
   | where match(Properties, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")
   | stats count by ObjectName
   | eval accounts_dumped=ObjectName
   ```

2. **Determine How Account Gained Permissions**:
   - Check for recent privilege escalation
   - Review account's group memberships
   - Check for ACL modifications on domain object

3. **Check for Golden Ticket Creation**:
   - Was krbtgt hash dumped?
   - Evidence of Golden Ticket usage?
   - See UC-AD-001 response

**Phase 3: Eradication**

1. **Reset Passwords for Dumped Accounts**:
   ```powershell
   # If krbtgt was dumped
   ./New-KrbtgtKeys.ps1 -Mode Reset

   # All admin account passwords
   Get-ADUser -Filter {AdminCount -eq 1} |
     ForEach-Object { Set-ADAccountPassword $_.SamAccountName -Reset }
   ```

2. **Remove Excessive Permissions**:
   ```powershell
   # Review and remove replication permissions
   Get-ADUser -Identity [account] -Properties *
   # Check group memberships
   # Remove from privileged groups if not needed
   ```

3. **Review ACLs on Domain Object**:
   ```powershell
   # Check for unauthorized replication permissions
   (Get-Acl "AD:\DC=company,DC=com").Access |
     Where-Object {$_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"}
   ```

### Escalation Criteria

**Immediate Escalation if**:
- krbtgt account was dumped
- Multiple admin accounts dumped
- Evidence of credential use
- Unknown account with replication rights

### Prevention

- Audit replication permissions regularly
- Limit membership of privileged groups
- Monitor Event 4662 in real-time
- Implement Protected Users group
- Use Tier 0 access model

---

## UC-AD-004: Kerberoasting Attack

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AD-004 |
| **Name** | Kerberoasting Attack |
| **Category** | Credential Access |
| **Severity** | High |
| **MITRE ATT&CK** | T1558.003 |
| **Detection IDs** | DET-KRB-001 |

### Description

Kerberoasting allows attackers to request service tickets for accounts with Service Principal Names (SPNs), then crack the tickets offline to obtain passwords.

### Attack Scenario

**Phase 1 - SPN Enumeration**:
```powershell
# Enumerate accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

**Phase 2 - Request Service Tickets**:
```powershell
# Request tickets for all SPNs
Add-Type -AssemblyName System.IdentityModel
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} | ForEach-Object {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.ServicePrincipalName
}
```

**Phase 3 - Extract and Crack**:
```powershell
# Export tickets
mimikatz # kerberos::list /export

# Crack with hashcat
hashcat -m 13100 tickets.txt wordlist.txt
```

### Response Procedure

**Immediate Actions**:
1. Disable requesting account
2. Isolate source system
3. Reset ALL SPN account passwords
4. Monitor for credential use

**Investigation**:
- Identify all SPNs requested
- Check password strength of service accounts
- Review account for compromise indicators

**Remediation**:
- Implement Group Managed Service Accounts (gMSA)
- Use 25+ character passwords for SPNs
- Enable AES encryption for Kerberos
- Regular password rotation

### Prevention

```powershell
# Implement gMSA for services
New-ADServiceAccount -Name ServiceAccount -DNSHostName server.company.com -PrincipalsAllowedToRetrieveManagedPassword "Servers"

# Monitor for weak passwords on SPNs
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} |
  Select Name, @{n='PasswordAge';e={(Get-Date) - $_.PasswordLastSet}}
```

---

## Summary - Active Directory Use Cases

| UC ID | Attack | Impact | Response Time | Complexity |
|-------|--------|--------|---------------|------------|
| UC-AD-001 | Golden Ticket | Domain Compromise | <15 min | Critical |
| UC-AD-002 | DCSync | All Credentials | <15 min | High |
| UC-AD-003 | AdminSDHolder | Persistence | <30 min | Medium |
| UC-AD-004 | Kerberoasting | Service Accounts | <1 hour | Medium |
| UC-AD-005 | Silver Ticket | Service Access | <1 hour | Medium |
| UC-AD-006 | AS-REP Roasting | Weak Accounts | <2 hours | Low |
| UC-AD-007 | NTDS.dit Theft | All Credentials | <15 min | Critical |
| UC-AD-008 | GPO Abuse | Persistence/Lateral | <30 min | Medium |
| UC-AD-009 | DCShadow | AD Modification | <15 min | Critical |
| UC-AD-010 | Skeleton Key | Master Password | <15 min | Critical |

---

**Use Case Repository Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Active Directory Security Team
**Total AD Use Cases**: 10
