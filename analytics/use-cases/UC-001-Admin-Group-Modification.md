# UC-001: Local Administrator Group Modification

## Overview

**Use Case ID**: UC-001
**Name**: Unauthorized Local Administrator Group Modification
**Severity**: High
**MITRE ATT&CK**: T1098.002 (Account Manipulation - Domain Account), T1136.001 (Create Account - Local)
**Analytics**: ANALYTIC-001
**Detection Method**: Windows Event Log 4728 (Group Membership Change)

### Description
Detects unauthorized addition of user accounts to local or domain administrative groups. This is a critical indicator of privilege escalation or persistence attempts by adversaries.

### Business Impact
- **High**: Unauthorized admin access can lead to:
  - Data exfiltration
  - System compromise
  - Lateral movement
  - Persistence mechanisms
  - Regulatory compliance violations

## Detection Strategy

### Data Sources Required
- Windows Security Event Logs (Event ID 4728)
- Active Directory audit logs
- Change management tickets (JIRA/ServiceNow)

### Detection Logic
Monitor for Event ID 4728 (Member added to security-enabled global group) and correlate with:
- Approved change tickets
- Known service accounts
- Business hours activity
- User role baseline

### Coverage
- **Platforms**: Windows Server, Domain Controllers
- **Accounts**: All user and service accounts
- **Groups**: Local Administrators, Domain Admins, Enterprise Admins, custom admin groups

## Investigation Runbook

### Phase 1: Immediate Actions (0-5 minutes)
1. **Confirm Group Membership Change**
   ```powershell
   Get-LocalGroupMember -Group "Administrators" | Where Name -like "*TargetUser*"
   ```
   - Verify timestamp matches alert
   - Check if account still in group

2. **Check Change Ticket**
   - Search JIRA/ServiceNow for related change request
   - Verify approval chain
   - Confirm authorized personnel

3. **Initial Context**
   - Who performed action? (SubjectUserName from Event 4728)
   - Business hours or after-hours?
   - Expected behavior for this user?

### Phase 2: Contextual Investigation (5-15 minutes)
1. **Actor Analysis**
   ```spl
   index=windows SubjectUserName="[ACTOR]" earliest=-24h
   | stats count by EventCode, TargetUserName, Computer
   ```
   - Review all actions by SubjectUserName in last 24h
   - Look for suspicious logons (Event 4624)
   - Check for other privilege changes

2. **Target Account Analysis**
   ```powershell
   Get-ADUser -Identity [TargetUser] -Properties * |
     Select Name, Enabled, Created, LastLogonDate, MemberOf
   ```
   - When was account created?
   - Last logon timestamp
   - Current group memberships
   - Account enabled status

3. **Historical Baseline**
   - Compare to normal frequency of admin additions
   - Check if similar changes in past week
   - Review patterns (same actor, time of day)

### Phase 3: Determine Legitimacy (15-30 minutes)
1. **Verify Authorization**
   - Contact requesting manager (from change ticket)
   - Confirm business justification
   - Verify approval process followed

2. **Service Account Check**
   ```
   Is TargetUserName in approved_service_accounts.csv?
   Is SubjectUserName in approved_provisioners.csv?
   ```

3. **Context Correlation**
   - New employee onboarding?
   - System maintenance window?
   - Documented admin delegation?

### Phase 4: Response Decision (30-45 minutes)

#### If AUTHORIZED (True Negative)
- Document in JIRA: Change ticket number, approver
- Update whitelist if recurring legitimate pattern
- Close as False Positive with justification

#### If UNAUTHORIZED (True Positive → Escalate to Incident)
- **Immediate**: Remove unauthorized account from group
  ```powershell
  Remove-LocalGroupMember -Group "Administrators" -Member "[TargetUser]"
  ```
- **Document**: Full timeline, evidence, actors
- **Escalate**: Create Incident (not just Alert)
- **Contain**: Follow RE&CT RA3xxx actions

## Response Actions (RE&CT Mapping)

| Phase | Action | RE&CT Code | Description |
|-------|--------|------------|-------------|
| **Identification** | Document account addition | RA1001 | Collect Event 4728, change ticket, AD snapshot |
| **Identification** | Identify all actors involved | RA1002 | Map SubjectUserName, TargetUserName, approval chain |
| **Identification** | Determine incident type | RA1003 | Privilege escalation vs legitimate change |
| **Containment** | Revoke unauthorized privileges | RA3101 | Remove from admin group immediately |
| **Eradication** | Reset account password | RA4101 | Force password reset for TargetUserName |
| **Recovery** | Restore baseline membership | RA5101 | Verify only authorized admins in group |
| **Lessons Learned** | Document in PIR | RA6001 | Update procedures, detection tuning |

## Escalation Criteria

### Escalate to INCIDENT if:
- ✅ Unauthorized addition (no change ticket OR no approval)
- ✅ Evidence of malicious activity (credential access, lateral movement)
- ✅ Multiple accounts added by same actor
- ✅ After-hours activity by non-admin user
- ✅ Known compromised account (from other alerts)

### Escalate to EXECUTIVE if:
- ✅ Tier-1 admin group affected (Domain Admins, Enterprise Admins)
- ✅ Cross-domain scope (multiple DCs, forests)
- ✅ Evidence of credential theft (correlated with UC-004)
- ✅ Data exfiltration indicators (correlated with UC-006)

### CLOSE as False Positive if:
- ✅ Valid change ticket with proper approval
- ✅ Documented business need
- ✅ Known service account provisioning
- ✅ Help desk during approved onboarding window

## Known False Positives

### 1. Help Desk Provisioning
- **Pattern**: SubjectUserName in approved_provisioners.csv
- **Timing**: Business hours (8am-6pm)
- **Frequency**: 1-2 per week
- **Mitigation**: Whitelist approved help desk accounts

### 2. Delegation During Admin Absence
- **Pattern**: Change ticket exists, temporary elevation
- **Duration**: Limited time period (e.g., 1 week vacation)
- **Approval**: Manager + IT Director
- **Mitigation**: Document and monitor for removal after period

### 3. Automated Onboarding
- **Pattern**: ServiceNow/JIRA automation account
- **Timing**: Correlated with HR system new hire records
- **Frequency**: Predictable based on hiring
- **Mitigation**: Whitelist automation accounts, verify HR correlation

### 4. System/Service Accounts
- **Pattern**: DC$ computer accounts, SYSTEM
- **Context**: Windows Update, replication
- **Mitigation**: Exclude computer accounts ending in $

## Tuning Guidance

### Week 1-2: Baseline Collection
- Run detection without alerting
- Document all group additions
- Categorize: legitimate vs suspicious
- Build whitelist: `approved_admin_provisioners.csv`

### Week 3-4: Initial Tuning
- Enable alerting with whitelists
- Monitor false positive rate (target <30%)
- Adjust time-based filters (business hours)
- Refine service account exclusions

### Ongoing Maintenance
- Monthly review of whitelists
- Update for new provisioning accounts
- Adjust thresholds based on org changes
- Document new legitimate patterns

## Success Metrics

- **Detection Rate**: 100% of unauthorized admin additions
- **True Positive Rate**: >70% after 4-week tuning
- **Mean Time to Triage**: <15 minutes
- **Mean Time to Respond**: <45 minutes (if unauthorized)
- **False Positive Rate**: <30% after tuning

## Correlation Opportunities

### High-Confidence Attack Chain
```
UC-003 (Credential Access) → UC-001 (Admin Group Add) → UC-005 (Lateral Movement)

If ANALYTIC-004 (Credential Dumping) fires:
  AND ANALYTIC-001 fires within 24h:
    → AUTO-ESCALATE to Critical Incident
    → Notify IR Team immediately
```

### Insider Threat Indicators
```
UC-001 (Admin Add) + UC-006 (Data Exfiltration) + After-hours activity
  → Flag for Insider Threat investigation
```

## NIST CSF Mapping
- **Detect (DE)**:
  - DE.AE-02: Potentially adverse events analyzed
  - DE.CM-01: Networks and network services monitored
- **Respond (RS)**:
  - RS.AN-03: Analysis performed to establish timeline
  - RS.MI-01: Incidents contained

## PICERL Phase: Identification → Containment
- **Preparation**: Whitelists, playbooks, automation configured
- **Identification**: ANALYTIC-001 triggers, runbook executed
- **Containment**: If unauthorized, revoke privileges (RA3101)
- **Eradication**: Reset credentials (RA4101)
- **Recovery**: Restore baseline (RA5101)
- **Lessons Learned**: PIR, detection tuning (RA6001)

## References
- KB-0001: Admin Group Modification Response Playbook
- ANALYTIC-001: Detection rule documentation
- RE&CT Framework: RA1xxx, RA3xxx, RA4xxx, RA5xxx, RA6xxx
- MITRE ATT&CK: T1098, T1136
- Windows Event 4728 Documentation

---
**Version**: 1.0
**Last Updated**: 2025-12-14
**Owner**: SOC Operations
**Review Cycle**: Monthly
