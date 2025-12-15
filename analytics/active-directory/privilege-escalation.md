# Active Directory Privilege Escalation Detections

## Overview

Detections for unauthorized privilege escalation in Active Directory environments.

---

## DET-AD-001: Unauthorized Addition to Privileged Groups

### Overview
- **Detection ID**: DET-AD-001
- **MITRE ATT&CK**: T1098 (Account Manipulation), T1078.002 (Domain Accounts)
- **Severity**: Critical
- **Data Sources**: Windows Security Event Logs, AD Audit Logs

### Description

Detects when a user is added to a privileged Active Directory group (Domain Admins, Enterprise Admins, etc.) outside of approved change management processes. This is a critical indicator of privilege escalation.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4728 OR EventCode=4732 OR EventCode=4756
| eval privileged_group=case(
    match(Group_Name, "(?i)domain admins"), "Domain Admins",
    match(Group_Name, "(?i)enterprise admins"), "Enterprise Admins",
    match(Group_Name, "(?i)schema admins"), "Schema Admins",
    match(Group_Name, "(?i)administrators"), "Administrators",
    match(Group_Name, "(?i)account operators"), "Account Operators",
    match(Group_Name, "(?i)backup operators"), "Backup Operators",
    match(Group_Name, "(?i)server operators"), "Server Operators",
    match(Group_Name, "(?i)print operators"), "Print Operators",
    1=1, null()
)
| where isnotnull(privileged_group)
| eval SubjectUserName=coalesce(SubjectUserName, user)
| eval TargetUserName=coalesce(TargetUserName, target_user)
| eval ComputerName=coalesce(ComputerName, dest)
| search NOT [ | inputlookup approved_admin_additions.csv | fields SubjectUserName, TargetUserName ]
| table _time, ComputerName, privileged_group, SubjectUserName, TargetUserName, EventCode
| sort - _time
```

### Notable Event Configuration

```
Title: Unauthorized Addition to Privileged Group - $TargetUserName$ added to $privileged_group$
Description: User $TargetUserName$ was added to privileged AD group $privileged_group$ by $SubjectUserName$ on $ComputerName$. This action was not found in approved change management records.
Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1098, T1078.002

Recommended Actions:
1. Contact $SubjectUserName$ immediately to verify authorization
2. Review approval records for change management ticket
3. If unauthorized, immediately remove $TargetUserName$ from group
4. Investigate $SubjectUserName$ account for compromise
5. Review all recent actions by both accounts
6. Create JIRA incident ticket
```

### False Positives

**Common FP Scenarios**:
1. Legitimate admin onboarding during business hours
2. Authorized privilege escalation for maintenance
3. Automated service account management

**Exclusions**:

Create lookup file `approved_admin_additions.csv`:
```csv
SubjectUserName,TargetUserName,Reason
admin_sa,new_admin_user,Approved Change CHG0012345
automation_svc,backup_admin,Automated Provisioning
```

Update SPL with exclusion:
```spl
| search NOT [ | inputlookup approved_admin_additions.csv | fields SubjectUserName, TargetUserName ]
```

### Tuning Guidance

1. **Whitelist Service Accounts**: Add approved automation accounts to exclusion list
2. **Business Hours**: Consider alert suppression during maintenance windows
3. **Change Management Integration**: Auto-populate approved additions from change management system
4. **Threshold**: Single occurrence is sufficient for critical groups

### Response Actions

**Immediate (0-15 minutes)**:
1. Verify with user who performed action
2. Check for active change management approval
3. If unauthorized: Remove user from group immediately
4. Revoke sessions for both users
5. Escalate to IR team

**Investigation (15-60 minutes)**:
1. Review authentication logs for both accounts
2. Check for other suspicious activities
3. Identify if accounts compromised
4. Review audit logs for other privilege changes
5. Document timeline

**Playbook**: [Admin Privilege Escalation Response](../../playbooks/admin-abuse/privilege-escalation.md)

### SOAR Integration

**Automated Actions**:
```python
# Splunk SOAR Playbook: privilege_escalation_response

# 1. Enrich - Get user details
phantom.get_user_attributes(user=target_user)

# 2. Containment - Disable account (if not approved)
if not approved_change:
    phantom.disable_user(user=target_user)
    phantom.revoke_user_sessions(user=target_user)

# 3. Notification
phantom.send_email(
    to="soc-critical@company.com",
    subject=f"CRITICAL: Unauthorized privilege escalation - {target_user}",
    body=alert_details
)

# 4. Create JIRA ticket
phantom.create_jira_ticket(
    project="SOC",
    issue_type="Incident",
    severity="Critical",
    summary=f"Unauthorized privilege escalation: {target_user} added to {group}",
    description=full_context
)

# 5. Gather evidence
phantom.run_query(query=f"Get all events for user {target_user} last 24h")
```

---

## DET-AD-002: Self-Service Admin Rights Grant

### Overview
- **Detection ID**: DET-AD-002
- **MITRE ATT&CK**: T1098 (Account Manipulation)
- **Severity**: Critical
- **Data Sources**: Windows Security Event Logs

### Description

Detects when a user adds themselves to a privileged group - a clear indicator of account compromise or malicious insider activity.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| eval privileged_group=case(
    match(Group_Name, "(?i)domain admins"), "Domain Admins",
    match(Group_Name, "(?i)enterprise admins"), "Enterprise Admins",
    match(Group_Name, "(?i)schema admins"), "Schema Admins",
    match(Group_Name, "(?i)administrators"), "Administrators",
    match(Group_Name, "(?i)backup operators"), "Backup Operators",
    match(Group_Name, "(?i)account operators"), "Account Operators",
    1=1, null()
)
| where isnotnull(privileged_group)
| eval SubjectUserName=lower(SubjectUserName)
| eval TargetUserName=lower(TargetUserName)
| where SubjectUserName=TargetUserName
| table _time, ComputerName, privileged_group, SubjectUserName, EventCode, SubjectDomainName
| eval description="User granted themselves admin privileges"
| sort - _time
```

### Notable Event Configuration

```
Title: CRITICAL - Self-Service Admin Rights Grant by $SubjectUserName$
Description: User $SubjectUserName$ added themselves to privileged group $privileged_group$ on $ComputerName$. This is an extremely high-confidence indicator of compromise or malicious activity.
Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1098

Recommended Actions:
1. IMMEDIATELY disable account $SubjectUserName$
2. Revoke all active sessions
3. Remove from ALL privileged groups
4. Investigate all actions performed by this account
5. Escalate to Incident Response Team immediately
6. Treat as confirmed security incident
```

### False Positives

**Extremely Rare** - This detection should have near-zero false positives. Any occurrence should be treated as malicious unless proven otherwise.

Possible legitimate scenarios:
- Testing in isolated lab environment only
- Authorized security testing/red team with approval

### Response Actions

**IMMEDIATE (0-5 minutes)**:
1. Disable account immediately
2. Remove from all privileged groups
3. Revoke all sessions and tokens
4. Alert IR team and management
5. Preserve logs and evidence

**Playbook**: [Self-Administration Incident Response](../../playbooks/admin-abuse/self-administration.md)

### SOAR Integration

```python
# Automatic containment for self-service admin grants

# 1. IMMEDIATE - Disable account (no approval needed)
phantom.disable_user(user=subject_user)

# 2. Remove from ALL admin groups
phantom.remove_from_all_admin_groups(user=subject_user)

# 3. Revoke all sessions
phantom.revoke_all_sessions(user=subject_user)

# 4. CRITICAL notifications
phantom.send_sms(to=oncall_ir_team, message=f"CRITICAL: Self-admin grant by {subject_user}")
phantom.send_email(to=["soc-critical@company.com", "ciso@company.com"])
phantom.create_incident(severity="critical", auto_escalate=True)

# 5. Evidence collection
phantom.get_user_activity(user=subject_user, hours=24)
phantom.get_login_history(user=subject_user, hours=72)
phantom.get_group_modifications(hours=1)
```

---

## DET-AD-003: Unauthorized Group Policy Modification

### Overview
- **Detection ID**: DET-AD-003
- **MITRE ATT&CK**: T1484 (Domain Policy Modification)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs, AD Audit Logs

### Description

Detects unauthorized modifications to Group Policy Objects, which can be used for privilege escalation, persistence, or lateral movement.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=5136
| where ObjectClass="groupPolicyContainer"
| eval AttributeChanged=AttributeLDAPDisplayName
| eval NewValue=AttributeValue
| eval ModifiedBy=SubjectUserName
| eval GPO_DN=ObjectDN
| search NOT [ | inputlookup authorized_gpo_admins.csv | fields ModifiedBy ]
| table _time, ComputerName, GPO_DN, AttributeChanged, NewValue, ModifiedBy, SubjectDomainName
| eval description="Unauthorized Group Policy modification detected"
| sort - _time
```

### Notable Event Configuration

```
Title: Unauthorized Group Policy Modification by $ModifiedBy$
Description: User $ModifiedBy$ modified Group Policy Object: $GPO_DN$. Attribute changed: $AttributeChanged$. This action was performed by a user not in the authorized GPO administrators list.
Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1484

Recommended Actions:
1. Verify modification was authorized
2. Review change management approvals
3. Inspect GPO changes for malicious content
4. Check for scheduled tasks, scripts, or startup items
5. If unauthorized, revert changes immediately
6. Investigate user account for compromise
```

### Tuning Guidance

Create `authorized_gpo_admins.csv`:
```csv
ModifiedBy,Role,Department
gpo_admin01,Group Policy Administrator,IT Operations
gpo_admin02,Group Policy Administrator,IT Operations
automation_svc,Automation Service Account,IT Automation
```

### Response Actions

1. Review GPO modification details
2. Check for malicious content (scripts, scheduled tasks)
3. Verify against change management
4. Revert if unauthorized
5. Investigate account

---

## DET-AD-004: Privileged Account Activity Outside Business Hours

### Overview
- **Detection ID**: DET-AD-004
- **MITRE ATT&CK**: T1078.002 (Domain Accounts)
- **Severity**: Medium (High if confirmed unauthorized)
- **Data Sources**: Windows Security Event Logs

### Description

Detects privileged account usage outside normal business hours, which may indicate compromised credentials or unauthorized access.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3 OR Logon_Type=10
| lookup privileged_accounts.csv Account_Name AS TargetUserName OUTPUT is_privileged
| where is_privileged="true"
| eval hour=tonumber(strftime(_time, "%H"))
| eval day=strftime(_time, "%A")
| where (hour < 6 OR hour > 20) OR (day="Saturday" OR day="Sunday")
| search NOT [ | inputlookup approved_afterhours_activity.csv | fields TargetUserName, date ]
| table _time, TargetUserName, ComputerName, IpAddress, Logon_Type, WorkstationName
| eval alert_reason="Privileged account activity outside business hours"
| sort - _time
```

### Lookup Tables

**privileged_accounts.csv**:
```csv
Account_Name,is_privileged,role
admin_user01,true,Domain Admin
admin_user02,true,Enterprise Admin
helpdesk_admin,false,Standard User
```

**approved_afterhours_activity.csv**:
```csv
TargetUserName,date,reason,approved_by
admin_user01,2025-12-14,Scheduled Maintenance,Change Manager
```

### Notable Event Configuration

```
Title: Privileged Account After-Hours Activity - $TargetUserName$
Description: Privileged account $TargetUserName$ logged in at $time$ from $IpAddress$ to $ComputerName$. This is outside normal business hours (6 AM - 8 PM Mon-Fri).
Severity: medium
Urgency: medium
Security Domain: access
MITRE ATT&CK: T1078.002

Recommended Actions:
1. Contact account owner to verify activity
2. Check for approved maintenance window
3. Review all actions performed during session
4. If unauthorized, disable account and investigate
5. Check for lateral movement or data access
```

### Tuning Guidance

1. **Define Business Hours**: Adjust hour ranges per organization
2. **Approved Maintenance**: Use lookup for scheduled maintenance
3. **Geographic Considerations**: Account for different time zones
4. **On-Call Rotations**: Exclude on-call admins if activity expected

---

## DET-AD-005: AdminSDHolder Modification

### Overview
- **Detection ID**: DET-AD-005
- **MITRE ATT&CK**: T1484 (Domain Policy Modification), T1078.002
- **Severity**: Critical
- **Data Sources**: Windows Security Event Logs

### Description

Detects modifications to the AdminSDHolder object, which can be used for persistence and maintaining admin access.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=5136
| where ObjectDN="CN=AdminSDHolder,CN=System,DC=*"
| eval AttributeChanged=AttributeLDAPDisplayName
| eval NewValue=AttributeValue
| eval ModifiedBy=SubjectUserName
| table _time, ComputerName, ObjectDN, AttributeChanged, NewValue, ModifiedBy, SubjectDomainName
| eval description="AdminSDHolder object modified - persistence mechanism"
| sort - _time
```

### Notable Event Configuration

```
Title: CRITICAL - AdminSDHolder Modification Detected
Description: The AdminSDHolder object was modified by $ModifiedBy$. Attribute: $AttributeChanged$. This is a critical security control and modifications can be used for persistence.
Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1484, T1078.002

Recommended Actions:
1. IMMEDIATELY investigate $ModifiedBy$ account
2. Review changes to AdminSDHolder
3. Check for unauthorized ACL modifications
4. Verify all protected accounts
5. Run SDProp manually if needed
6. Escalate to Incident Response Team
```

### Response Actions

1. Immediate investigation of modifier account
2. Review AdminSDHolder ACL changes
3. Check protected admin accounts
4. Run SDProp if malicious changes detected
5. Full account compromise investigation

---

## DET-AD-006: Suspicious dsacls Usage

### Overview
- **Detection ID**: DET-AD-006
- **MITRE ATT&CK**: T1484 (Domain Policy Modification)
- **Severity**: High
- **Data Sources**: Sysmon, Windows Security

### Description

Detects usage of dsacls.exe to modify Active Directory permissions, often used for privilege escalation.

### SPL Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)dsacls")
| eval is_suspicious=if(match(CommandLine, "(?i)(\/G|\/R|\/P|\/D)"), "true", "false")
| where is_suspicious="true"
| rex field=CommandLine "(?<target_object>CN=.+?(?=\s|$))"
| table _time, User, ComputerName, CommandLine, target_object, ParentCommandLine, ParentImage
| eval description="dsacls.exe used to modify AD permissions"
| sort - _time
```

### Notable Event Configuration

```
Title: Suspicious dsacls Usage by $User$
Description: User $User$ executed dsacls.exe on $ComputerName$ to modify AD permissions. Command: $CommandLine$. This may indicate privilege escalation attempt.
Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1484

Recommended Actions:
1. Review command line for target object and permissions granted
2. Verify activity is authorized
3. Check what permissions were added/modified
4. Investigate $User$ account for compromise
5. Review all recent actions by this account
```

---

## Additional Critical AD Detections

### DET-AD-007: DCSync Attack Detection
- Monitors for non-DC accounts requesting AD replication
- Event IDs: 4662 with specific GUIDs
- Critical severity

### DET-AD-008: Mimikatz DCSync Detection
- Looks for specific directory service access patterns
- GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
- Critical severity

### DET-AD-009: NTDS.dit Access
- Detects unauthorized access to ntds.dit file
- File access and copy attempts
- Critical severity

### DET-AD-010: Kerberos Ticket Abnormalities
- See `kerberos-attacks.md` for detailed Kerberos detections
- Golden ticket, Silver ticket, Kerberoasting

---

## Summary Statistics

| Detection ID | Name | Severity | FP Rate | Deployment Priority |
|--------------|------|----------|---------|-------------------|
| DET-AD-001 | Unauthorized Privileged Group Addition | Critical | Low | 1 |
| DET-AD-002 | Self-Service Admin Grant | Critical | Very Low | 1 |
| DET-AD-003 | GPO Modification | High | Medium | 2 |
| DET-AD-004 | After-Hours Admin Activity | Medium | Medium | 3 |
| DET-AD-005 | AdminSDHolder Modification | Critical | Very Low | 1 |
| DET-AD-006 | dsacls Usage | High | Low | 2 |

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
