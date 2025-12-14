# Admin Abuse & Privilege Escalation Use Cases

## Overview

This directory contains detailed use cases for detecting and responding to administrative privilege abuse, unauthorized privilege escalation, and policy violations.

## Use Case Index

### Critical Priority (P1)

1. **[UC-AA-001: Unauthorized Self-Service Admin Rights Grant](#uc-aa-001)**
   - User adds themselves to admin group
   - Severity: Critical
   - MITRE: T1098

2. **[UC-AA-002: Unauthorized Privilege Escalation](#uc-aa-002)**
   - Adding users to privileged groups without approval
   - Severity: Critical
   - MITRE: T1078.002, T1098

3. **[UC-AA-003: AdminSDHolder Tampering](#uc-aa-003)**
   - Modification of AdminSDHolder for persistence
   - Severity: Critical
   - MITRE: T1484

### High Priority (P2)

4. **[UC-AA-004: Admin Account Activity Outside Business Hours](#uc-aa-004)**
   - Privileged account usage at unusual times
   - Severity: High
   - MITRE: T1078.002

5. **[UC-AA-005: Admin Account on Non-Admin Workstation](#uc-aa-005)**
   - Admin credentials used on standard workstations
   - Severity: High
   - MITRE: T1078

6. **[UC-AA-006: Unauthorized Administrative Tool Usage](#uc-aa-006)**
   - Execution of admin/hacking tools without authorization
   - Severity: High
   - MITRE: T1588.002

7. **[UC-AA-007: Group Policy Unauthorized Modification](#uc-aa-007)**
   - GPO changes without approval
   - Severity: High
   - MITRE: T1484

### Medium Priority (P3)

8. **[UC-AA-008: Admin Account Used for Non-Admin Tasks](#uc-aa-008)**
   - Privileged account misuse for browsing, email, etc.
   - Severity: Medium
   - MITRE: T1078

9. **[UC-AA-009: Excessive Failed Admin Authentication](#uc-aa-009)**
   - Multiple failed logon attempts for admin accounts
   - Severity: Medium
   - MITRE: T1110

10. **[UC-AA-010: Security Software Disabled](#uc-aa-010)**
    - AV, EDR, or firewall disabled
    - Severity: High (upgraded from Medium if unauthorized)
    - MITRE: T1562.001

---

## UC-AA-001: Unauthorized Self-Service Admin Rights Grant

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AA-001 |
| **Name** | Unauthorized Self-Service Admin Rights Grant |
| **Category** | Admin Abuse, Privilege Escalation |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1098 (Account Manipulation) |
| **Detection ID** | DET-AD-002 |

### Description

Detects when a user adds themselves to a privileged Active Directory security group. This is an extremely high-confidence indicator of account compromise or malicious insider activity, as legitimate administrative processes never involve self-service privilege grants.

### Attack Scenario

**Attacker Goal**: Obtain administrative privileges

**Attack Steps**:
1. Attacker compromises standard user account
2. Discovers account has permission to modify AD groups (misconfiguration)
3. Adds their own account to "Domain Admins" or similar group
4. Now has full administrative access to domain

**Alternative Scenario - Malicious Insider**:
1. Privileged user abuses their permissions
2. Grants themselves unauthorized elevated privileges
3. Performs unauthorized actions
4. May cover tracks by removing themselves from group

### Detection Logic

**Primary Detection**:
```spl
EventCode=4728 OR EventCode=4732 OR EventCode=4756
WHERE SubjectUserName = TargetUserName
AND Group_Name IN (Domain Admins, Enterprise Admins, etc.)
```

**Key Indicators**:
- Subject (actor) and Target (affected user) are the same
- Group is a privileged security group
- Action is "Member Added"

**Data Sources**:
- Windows Security Event Logs (EventCode 4728, 4732, 4756)
- Active Directory audit logs

### Response Procedure

**Phase 1: Immediate Containment (0-5 minutes)**

1. **Disable Account**:
   ```powershell
   Disable-ADAccount -Identity <username>
   ```

2. **Remove from ALL Privileged Groups**:
   ```powershell
   # Get all groups
   $groups = Get-ADUser -Identity <username> -Properties MemberOf | Select -ExpandProperty MemberOf

   # Remove from each
   foreach ($group in $groups) {
       Remove-ADGroupMember -Identity $group -Members <username> -Confirm:$false
   }
   ```

3. **Revoke All Active Sessions**:
   ```powershell
   Revoke-AzureADUserAllRefreshToken -ObjectId <user@domain.com>
   ```

**Phase 2: Investigation (5-30 minutes)**

1. **Timeline Construction**:
   - When was account compromised?
   - When did self-grant occur?
   - What actions were performed with admin rights?

2. **Review Audit Logs**:
   ```spl
   index=windows EventCode=4624 OR EventCode=4672 OR EventCode=4688
   | where TargetUserName="<username>"
   | table _time, EventCode, ComputerName, IpAddress, Process_Name
   ```

3. **Check for Lateral Movement**:
   - Did user access other systems?
   - Were credentials dumped?
   - Was malware deployed?

4. **Examine Account History**:
   - Review login patterns
   - Check for unusual source IPs
   - Identify potential compromise vector

**Phase 3: Eradication**

1. **Reset Password**:
   ```powershell
   Set-ADAccountPassword -Identity <username> -Reset
   ```

2. **Force Kerberos Ticket Refresh**:
   ```powershell
   Set-ADUser -Identity <username> -Replace @{msDS-KeyVersionNumber=0}
   ```

3. **Review All Administrative Actions**:
   - Check for backdoor accounts created
   - Review GPO modifications
   - Check for scheduled tasks
   - Examine service accounts

4. **Scan Systems Accessed**:
   - Full malware scan on any systems accessed
   - Check for persistence mechanisms

**Phase 4: Recovery**

1. Re-enable account only after:
   - Password reset completed
   - MFA re-registered
   - User interviewed and educated
   - No signs of ongoing compromise

2. Enhanced Monitoring:
   - Monitor account for 30 days
   - Alert on any privilege changes
   - Review all authentication events

**Phase 5: Post-Incident**

1. **Root Cause Analysis**:
   - How did account gain permission to modify groups?
   - Was it a misconfiguration?
   - Insider threat or compromised account?

2. **Remediation**:
   - Remove unnecessary permissions
   - Implement least privilege
   - Deploy Protected Users group
   - Enable privileged account monitoring

3. **Documentation**:
   - Complete PIR in Confluence
   - Update detection rules
   - Share lessons learned

### False Positives

**Extremely Rare** - This detection should have near-zero false positives.

Possible legitimate scenarios:
- Automated provisioning scripts running as user (bad practice)
- Testing in isolated lab environment

**Recommended Action**: Treat every occurrence as malicious unless proven otherwise with strong evidence and approval documentation.

### Escalation Criteria

**Automatic Escalation** - This use case ALWAYS requires immediate escalation:
- Notify SOC Lead immediately
- Alert Incident Response Team
- Inform CISO for critical accounts
- Law enforcement if insider threat suspected

### JIRA Workflow

1. **Auto-Create**: JIRA incident ticket (Severity: Critical)
2. **Status**: New → Triage (immediate)
3. **Assignment**: Incident Response Team
4. **SLA**: 15-minute response, 4-hour resolution

### Metrics

Track these metrics:
- Occurrences per month
- Time to detect (should be <5 minutes)
- Time to containment (should be <15 minutes)
- Source of compromise (phishing, malware, insider, etc.)
- Systems affected

### Prevention

**Technical Controls**:
- Remove delegated group modification permissions
- Use Protected Users group for admins
- Implement just-in-time admin access
- Deploy Privileged Access Management (PAM)
- Enable advanced AD auditing

**Process Controls**:
- Formal approval process for privilege grants
- Regular access reviews
- Segregation of duties
- Privileged account lifecycle management

**Detection Enhancements**:
- Real-time alerting (not batch)
- Automated containment via SOAR
- Correlation with authentication anomalies
- Behavioral baselining

### Related Use Cases

- UC-AA-002: Unauthorized Privilege Escalation
- UC-AA-003: AdminSDHolder Tampering
- UC-AD-001: Kerberoasting (potential follow-on)
- UC-AD-002: DCSync (potential follow-on)

### Playbooks

- [Admin Privilege Escalation Response](../../playbooks/admin-abuse/privilege-escalation.md)
- [Account Compromise Response](../../playbooks/compromised-account/PLAYBOOK.md)

### References

- MITRE ATT&CK T1098: https://attack.mitre.org/techniques/T1098/
- Microsoft AD Security Best Practices
- NIST SP 800-53: AC-2 (Account Management)

---

## UC-AA-002: Unauthorized Privilege Escalation

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AA-002 |
| **Name** | Unauthorized Addition to Privileged Groups |
| **Category** | Admin Abuse, Privilege Escalation |
| **Severity** | Critical |
| **MITRE ATT&CK** | T1098, T1078.002 |
| **Detection ID** | DET-AD-001 |

### Description

Detects when a user is added to a privileged Active Directory group by another user, outside of approved change management processes. While not as severe as self-service grants, unauthorized third-party privilege grants indicate compromised admin accounts or policy violations.

### Attack Scenario

**Scenario 1 - Compromised Admin Account**:
1. Attacker compromises IT admin account
2. Uses legitimate admin tools to grant privileges
3. Adds attacker-controlled account to Domain Admins
4. Maintains persistence through legitimate admin account

**Scenario 2 - Malicious Insider**:
1. IT administrator with privilege management rights
2. Unauthorized privilege grant to accomplice
3. Accomplice performs unauthorized actions
4. Both users cover tracks

**Scenario 3 - Social Engineering**:
1. Attacker socially engineers helpdesk
2. Unauthorized privilege grant via legitimate process
3. Attacker gains admin access
4. Exploits before detection

### Detection Logic

```spl
EventCode IN (4728, 4732, 4756)
WHERE Group_Name IN (Domain Admins, Enterprise Admins, Administrators, ...)
AND SubjectUserName NOT IN (approved_admin_list)
AND NOT EXISTS IN change_management_tickets
```

### Investigation Questions

1. **Who added the user?**
   - Is SubjectUserName a legitimate admin?
   - Is their account potentially compromised?
   - Was it an authorized action?

2. **Who was added?**
   - Is TargetUserName a new employee?
   - Contractor? Service account?
   - Known user needing legitimate elevation?

3. **Was there approval?**
   - Open change management ticket?
   - Email approval from manager?
   - Emergency change process followed?

4. **What happened after?**
   - Did new admin account perform any actions?
   - Suspicious activity?
   - Immediate logout (test) or sustained use?

### Response Procedure

**Immediate Actions**:
1. Contact SubjectUserName (the admin who made change)
2. Verify authorization via phone call (not email)
3. If unauthorized: Remove TargetUserName from group immediately
4. If SubjectUserName account compromised: Disable and investigate

**Investigation Steps**:
1. Review change management system for approval
2. Check SubjectUserName authentication logs for anomalies
3. Review TargetUserName activity since grant
4. Examine both accounts for signs of compromise

**Escalation Criteria**:
- No change management approval found
- Admin who made change cannot explain
- Either account shows signs of compromise
- Privileged actions performed by newly elevated account

### False Positives

**Common False Positives**:
1. Legitimate admin onboarding with verbal approval
2. Emergency access grant during incident
3. Automation script not in whitelist

**Tuning**:
- Maintain approved admin user whitelist
- Integrate with change management API
- Exception list for emergency contacts
- Time-based exceptions (e.g., maintenance windows)

### Integration with Change Management

**ServiceNow Example**:
```python
# Check if privilege grant has approval
import requests

def check_change_approval(subject_user, target_user, timestamp):
    # Query ServiceNow for change tickets
    response = requests.get(
        'https://company.service-now.com/api/now/table/change_request',
        params={
            'sysparm_query': f'requested_by={subject_user}^short_description CONTAINS {target_user}^sys_created_on>{timestamp}',
            'sysparm_fields': 'number,state,approval'
        },
        auth=('api_user', 'api_key')
    )

    if response.json()['result']:
        return True  # Approved change found
    else:
        return False  # No approval - alert!
```

### Metrics

- Unauthorized privilege grants per month
- % of grants with proper approvals
- Mean time to detect unauthorized grants
- False positive rate
- Most common violators (for training)

---

## UC-AA-004: Admin Account Activity Outside Business Hours

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AA-004 |
| **Name** | Admin Account Activity Outside Business Hours |
| **Category** | Admin Abuse, Policy Violation |
| **Severity** | Medium (High if confirmed unauthorized) |
| **MITRE ATT&CK** | T1078.002 |
| **Detection ID** | DET-AD-004 |

### Description

Detects privileged account usage outside defined business hours, which may indicate:
- Compromised credentials used by attacker in different timezone
- Unauthorized moonlighting by admin
- Automated tasks running as admin account (misconfiguration)

### Business Hours Definition

Define per organization:
- **Standard**: Monday-Friday, 6 AM - 8 PM local time
- **Exclude**: Holidays, scheduled maintenance windows
- **Exceptions**: On-call rotation, approved after-hours work

### Detection Logic

```spl
EventCode=4624 AND Logon_Type IN (2, 3, 10)
WHERE Account_Name IN (privileged_accounts)
AND (hour < 6 OR hour > 20) OR day IN (Saturday, Sunday)
AND NOT IN (approved_afterhours_schedule)
```

### Triage Process

**Level 1 - Automated Checks**:
1. Check if user is on-call this week
2. Check for open maintenance ticket
3. Check if activity is from admin workstation
4. Check for patterns of after-hours work

**Level 2 - Analyst Review** (if automated checks inconclusive):
1. Review what actions were performed
2. Check source IP/location
3. Examine authentication patterns
4. Compare to user's normal behavior

**Level 3 - User Contact** (if suspicious):
1. Contact user via phone
2. Verify they performed activity
3. Determine if account compromised
4. Escalate if needed

### Response Matrix

| Scenario | Action |
|----------|--------|
| On-call admin doing approved work | Document and close |
| Emergency response to incident | Verify and document |
| Scheduled maintenance | Check for approval, close |
| Unknown/unauthorized | Disable account, investigate |
| Unusual location/IP | Escalate for investigation |

### False Positive Reduction

**Whitelist Scenarios**:
```csv
User,DayOfWeek,StartHour,EndHour,Reason,Expiration
admin_oncall,*,*,*,On-call rotation,2025-12-31
backup_admin,Sunday,2,4,Weekly backup maintenance,2026-01-01
```

**Smart Alerting**:
- Suppress if user authenticated normally during business hours same day
- Suppress if activity is from known admin workstation
- Suppress if duration <5 minutes (possible legitimate check)
- Escalate if >2 hours of sustained activity

### Metrics

- After-hours admin activity volume
- % with approvals vs unauthorized
- False positive rate
- Detection to verification time
- Compromised accounts identified

---

## UC-AA-006: Unauthorized Administrative Tool Usage

### Use Case Summary

| Attribute | Value |
|-----------|-------|
| **Use Case ID** | UC-AA-006 |
| **Name** | Unauthorized Administrative/Hacking Tool Execution |
| **Category** | Admin Abuse, Policy Violation |
| **Severity** | High |
| **MITRE ATT&CK** | T1588.002 (Tool) |
| **Detection ID** | DET-POL-001 |

### Description

Detects execution of unauthorized administrative tools, penetration testing tools, or known hacking utilities that violate organizational security policy.

### Tool Categories

**Category 1 - Credential Access Tools** (Critical):
- Mimikatz, pwdump, fgdump, gsecdump
- LaZagne, CredNinja
- Rubeus, Kekeo

**Category 2 - Remote Execution Tools** (High):
- PsExec, PaExec, RemCom
- WinRM abuse tools
- WMIC abuse

**Category 3 - AD Enumeration Tools** (High):
- PowerView, SharpView
- BloodHound, SharpHound
- ADExplorer, AdFind

**Category 4 - Network Tools** (Medium-High):
- Nmap, Masscan
- Metasploit, Cobalt Strike, Empire
- Responder, Inveigh

**Category 5 - Process/Memory Tools** (High):
- ProcDump, Nanodump
- Process Hacker
- SQLDumper abuse

### Detection Methods

**Method 1 - Process Execution (Sysmon)**:
```spl
EventCode=1
WHERE Image MATCHES (mimikatz|psexec|bloodhound|nmap|...)
AND User NOT IN (authorized_security_testing)
```

**Method 2 - File Hash** (Most Reliable):
```spl
EventCode=1
WHERE SHA256 IN (known_tool_hashes)
```

**Method 3 - Command Line**:
```spl
EventCode=1
WHERE CommandLine MATCHES (invoke-mimikatz|Get-GPPPassword|...)
```

**Method 4 - Network Indicators**:
```spl
DNS queries to kali.org, offensive-security.com
Downloads from github.com/gentilkiwi/mimikatz
```

### Authorization Process

**Approved Use Cases**:
1. **Security Team Testing**:
   - Penetration testing engagement
   - Red team exercises
   - Vulnerability assessments

2. **Incident Response**:
   - Active incident investigation
   - Forensic analysis
   - Malware analysis (isolated environment)

3. **Security Research**:
   - Lab environment only
   - Documented research project

**Approval Requirements**:
- Written approval from CISO
- Scope document (systems, timeframe)
- Notification to SOC
- Post-activity report

**Whitelist Format**:
```csv
User,Tool,Hash,Justification,Approved_By,Start_Date,End_Date,Scope
security_analyst,mimikatz.exe,<SHA256>,Approved pentest,CISO,2025-12-01,2025-12-31,LAB network only
red_team_lead,bloodhound,<SHA256>,Red team exercise,CISO,2025-12-15,2025-12-20,Entire domain
```

### Response Procedure

**Tier 1 Response**:
1. Check whitelist for authorization
2. If authorized: Document and close
3. If unauthorized: Escalate to Tier 2

**Tier 2 Investigation**:
1. Isolate system immediately
2. Collect memory dump (before reboot!)
3. Capture running processes
4. Review tool execution context:
   - How was it obtained?
   - What actions did it perform?
   - What data was accessed?

**Tier 3 Incident Response** (if malicious):
1. Full forensic investigation
2. Determine compromise scope
3. Check for credential theft
4. Identify lateral movement
5. Eradicate and recover

### Tool-Specific Responses

**If Mimikatz Detected**:
```
CRITICAL ACTIONS:
1. ASSUME all credentials on system compromised
2. Isolate immediately (DO NOT reboot yet)
3. Capture memory dump
4. Reset passwords for:
   - All admin accounts that logged into system
   - Service accounts on system
   - Local admin password (LAPS)
5. Check for krbtgt password dumps (Golden Ticket)
6. Review all domain authentication for signs of use
```

**If PsExec Detected**:
```
INVESTIGATION:
1. Identify all target systems
2. Check for lateral movement
3. Review processes created via PsExec
4. Check for malware deployment
5. Verify legitimate vs malicious use
```

**If BloodHound Detected**:
```
ASSESSMENT:
1. AD reconnaissance occurred
2. Assume attack path identification
3. Review most privileged accounts
4. Check for follow-on exploitation
5. Harden attack paths identified
```

### Metrics

- Unauthorized tool detections per month
- % authorized (approved) vs unauthorized
- Tool categories detected
- Time to containment
- Compromises from tool abuse

---

## Summary Table - All Use Cases

| UC ID | Name | Severity | MITRE | Detection | Response Time |
|-------|------|----------|-------|-----------|---------------|
| UC-AA-001 | Self-Service Admin Grant | Critical | T1098 | DET-AD-002 | <15 min |
| UC-AA-002 | Unauthorized Privilege Escalation | Critical | T1098, T1078.002 | DET-AD-001 | <30 min |
| UC-AA-003 | AdminSDHolder Tampering | Critical | T1484 | DET-AD-005 | <15 min |
| UC-AA-004 | After-Hours Admin Activity | Medium | T1078.002 | DET-AD-004 | <2 hours |
| UC-AA-005 | Admin on Non-Admin WS | High | T1078 | DET-POL-002 | <1 hour |
| UC-AA-006 | Unauthorized Tools | High | T1588.002 | DET-POL-001 | <1 hour |
| UC-AA-007 | GPO Modification | High | T1484 | DET-AD-003 | <1 hour |
| UC-AA-008 | Admin Account Misuse | Medium | T1078 | DET-POL-003 | <4 hours |
| UC-AA-009 | Failed Admin Auth | Medium | T1110 | Custom | <2 hours |
| UC-AA-010 | Security Software Disabled | High | T1562.001 | DET-POL-006 | <30 min |

---

**Use Case Repository Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
**Total Use Cases**: 10
