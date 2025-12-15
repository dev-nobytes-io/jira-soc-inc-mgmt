# JIRA Automation Rules Configuration

## Overview

This document provides exportable/importable automation rule configurations for JIRA. These rules orchestrate the entire incident lifecycle from alert ingestion through closure.

## Architecture

```
Splunk Alert → JIRA Webhook → Automation Rules → Enrichment → Assignment → Playbook Linking → Monitoring
```

## Automation Rules

### RULE 1: Alert Ingestion & Enrichment

**Rule Name**: `AUTO-001: Alert Ingestion and Initial Enrichment`
**Trigger**: Issue created via webhook
**Scope**: All alerts from SIEM

#### Conditions
```
- Issue Type = "Alert"
- Summary contains pattern: "UC-[0-9]{3}"
- Detection Source is not empty
```

#### Actions

**Action 1: Parse Alert Metadata**
```groovy
// Extract Use Case ID from summary
def summary = issue.summary
def matcher = summary =~ /UC-(\d{3})/
if (matcher.find()) {
    def ucId = "UC-${matcher.group(1)}"
    issue.setCustomFieldValue("Use Case", ucId)
}

// Extract Analytic ID
matcher = summary =~ /ANALYTIC-(\d{3})/
if (matcher.find()) {
    def analyticId = "ANALYTIC-${matcher.group(1)}"
    issue.setCustomFieldValue("Detection Analytics", analyticId)
}
```

**Action 2: Set MITRE ATT&CK from Analytic**
```
Lookup table: analytic_to_attack_mapping.csv

IF Detection Analytics = "ANALYTIC-001":
  Set MITRE ATT&CK Techniques = "T1098.002, T1136.001"
  Set MITRE ATT&CK Tactics = "Persistence, Privilege Escalation"

IF Detection Analytics = "ANALYTIC-004":
  Set MITRE ATT&CK Techniques = "T1003.001"
  Set MITRE ATT&CK Tactics = "Credential Access"
```

**Action 3: Set Initial PICERL Phase**
```
Set PICERL Phase = "Identification"
Set Identification Start Time = {{now}}
```

**Action 4: Link Knowledge Base Playbook**
```
IF Use Case = "UC-001":
  Set Primary Playbook = "KB-0001"
  Set Knowledge Base References = "KB-0001"

IF Use Case = "UC-004":
  Set Primary Playbook = "KB-0042"
  Set Knowledge Base References = "KB-0042"
```

**Action 5: Add Investigation Comment**
```
Add comment:
---
🔍 **Alert Detected**
- **Detection**: {{Detection Analytics}}
- **Use Case**: {{Use Case}}
- **ATT&CK**: {{MITRE ATT&CK Techniques}}
- **Playbook**: {{Primary Playbook}}

**Next Steps**: Review playbook and begin triage
---
```

---

### RULE 2: Auto-Assignment Based on Use Case

**Rule Name**: `AUTO-002: Auto-Assign by Use Case and Severity`
**Trigger**: Issue created OR field value changed (Severity)
**Scope**: Alert, Incident

#### Conditions
```
- Use Case is not empty
- OR Severity changed
- Assignee is empty
```

#### Assignment Logic

**By Use Case**:
```
UC-001, UC-002, UC-003 → Tier 1 Analyst (Round Robin)
UC-004, UC-005 → Tier 2 Analyst (on-call rotation)
UC-006, UC-007 → Tier 3 / IR Team
```

**By Severity Override**:
```
IF Severity = "Critical":
  Assign to: IR Team Lead
  CC: CISO, SOC Manager

IF Severity = "High":
  Assign to: Senior Analyst (on-call)
  CC: SOC Manager

IF Severity = "Medium":
  Assign to: Tier 2 Analyst (round robin)

IF Severity = "Low":
  Assign to: Tier 1 Analyst (round robin)
```

**Action**: Send notification
```
Send email to {{Assignee}}:
Subject: [{{Severity}}] New SOC Alert: {{Summary}}
Body:
You have been assigned a new {{Severity}} alert.

Alert: {{key}}
Use Case: {{Use Case}}
Detection: {{Detection Analytics}}
Playbook: {{Primary Playbook}}

Review and begin triage within SLA.
```

---

### RULE 3: SLA Management

**Rule Name**: `AUTO-003: SLA Configuration by Severity`
**Trigger**: Issue created OR Severity changed
**Scope**: Alert, Incident

#### SLA Targets

**Alerts**:
```
Critical: 15 minutes to triage, 1 hour to respond
High: 30 minutes to triage, 4 hours to respond
Medium: 2 hours to triage, 8 hours to respond
Low: 4 hours to triage, 24 hours to respond
```

**Incidents**:
```
Critical: 1 hour to contain, 8 hours to eradicate
High: 4 hours to contain, 24 hours to eradicate
Medium: 8 hours to contain, 48 hours to eradicate
Low: 24 hours to contain, 72 hours to eradicate
```

#### Actions
```
Set SLA Response = {{now}} + [time based on severity]
Set SLA Resolution = {{now}} + [time based on severity]

IF 75% of SLA elapsed:
  Send warning notification to assignee
  CC: Team lead

IF 100% of SLA elapsed:
  Escalate to manager
  Add comment: "⚠️ SLA BREACH - Immediate attention required"
```

---

### RULE 4: PICERL Phase Automation

**Rule Name**: `AUTO-004: PICERL Phase Transitions`
**Trigger**: Status changed
**Scope**: Incident

#### Phase Mapping
```
Status → PICERL Phase → Actions

"New" → "Identification"
  - Set Identification Start = {{now}}
  - Add sub-task: "Complete investigation runbook"

"Triage" → "Identification"
  - Continue Identification phase

"Investigation" → "Identification"
  - Add comment: "Investigation in progress"

"Containment" → "Containment"
  - Set PICERL Phase = "Containment"
  - Set Containment Start = {{now}}
  - Calculate Identification Duration
  - Add sub-task checklist: RA3xxx actions
  - Set NIST CSF Function = "Respond (RS)"

"Eradication" → "Eradication"
  - Set PICERL Phase = "Eradication"
  - Set Eradication Start = {{now}}
  - Calculate Containment Duration
  - Add sub-task checklist: RA4xxx actions

"Recovery" → "Recovery"
  - Set PICERL Phase = "Recovery"
  - Set Recovery Start = {{now}}
  - Calculate Eradication Duration
  - Add sub-task checklist: RA5xxx actions
  - Set NIST CSF Function = "Recover (RC)"

"Post-Incident" → "Lessons Learned"
  - Set PICERL Phase = "Lessons Learned"
  - Set Lessons Learned Start = {{now}}
  - Calculate Recovery Duration
  - Add sub-task: "Schedule PIR meeting"
  - Add sub-task: "Document lessons learned"

"Closed" → "Lessons Learned"
  - Calculate Total Incident Duration
  - Set NIST CSF Function = "Govern (GV)"
  - Prompt for Playbook Effectiveness rating
```

---

### RULE 5: RE&CT Action Checklists

**Rule Name**: `AUTO-005: Create RE&CT Action Checklists`
**Trigger**: Status changed to Containment, Eradication, or Recovery
**Scope**: Incident

#### Containment Phase (RA3xxx)
```
When Status = "Containment":
  Create sub-tasks:

  ☐ RA3101: Disable Compromised Credentials
     - Reset password for affected accounts
     - Terminate active sessions
     - Document timestamp

  ☐ RA3201: Terminate Suspicious Processes
     - Identify malicious processes
     - Kill process tree
     - Prevent restart

  ☐ RA3301: Block Malicious IPs/Domains
     - Add firewall rules
     - Update DNS sinkhole
     - Verify block effectiveness
```

#### Eradication Phase (RA4xxx)
```
When Status = "Eradication":
  Create sub-tasks:

  ☐ RA4101: Full Credential Reset
     - Reset all potentially compromised credentials
     - Force password change at next logon
     - Document credential scope

  ☐ RA4201: Remove Malware/Persistence
     - Run AV scan
     - Remove persistence mechanisms
     - Verify eradication

  ☐ RA4401: Patch Exploitation Vector
     - Identify vulnerability
     - Apply patches
     - Verify remediation
```

#### Recovery Phase (RA5xxx)
```
When Status = "Recovery":
  Create sub-tasks:

  ☐ RA5001: Restore Systems
     - Restore from clean backup (if needed)
     - Verify integrity
     - Test functionality

  ☐ RA5101: Restore User Access
     - Re-enable accounts
     - Restore group memberships
     - Verify access works
```

---

### RULE 6: Critical Incident Escalation

**Rule Name**: `AUTO-006: Critical Incident Auto-Escalation`
**Trigger**: Multiple conditions met
**Scope**: Alert, Incident

#### Auto-Escalation Triggers

**Scenario 1: Credential Dumping + Admin Elevation**
```
IF ANALYTIC-004 (Credential Dumping) fires
  AND ANALYTIC-001 (Admin Group Add) fires within 24 hours
  AND same Computer/User correlation
THEN:
  - Create new Incident (if Alert)
  - Set Severity = "Critical"
  - Assign to IR Team Lead
  - Notify: CISO, SOC Manager, IR Team
  - Add comment: "🚨 CRITICAL: Potential privilege escalation attack chain detected"
  - Link related tickets
```

**Scenario 2: Lateral Movement Chain**
```
IF ANALYTIC-005 (Lateral Movement) fires
  AND >3 different destination hosts
  AND within 1-hour window
THEN:
  - Auto-escalate to Critical
  - Assign to IR Team
  - Add comment: "⚠️ Widespread lateral movement detected"
  - Create parent "Incident Campaign" issue
```

**Scenario 3: Data Exfiltration**
```
IF ANALYTIC-006 (Data Exfiltration) fires
  AND volume > 1GB
  OR destination in high-risk countries
THEN:
  - Set Severity = "Critical"
  - Notify: Legal, Compliance, CISO
  - Add label: "data-breach"
  - Create sub-task: "Assess regulatory notification requirements"
```

---

### RULE 7: Playbook Effectiveness Tracking

**Rule Name**: `AUTO-007: Request Playbook Effectiveness Rating`
**Trigger**: Issue transitioned to Closed
**Scope**: Incident

#### Conditions
```
- Status = "Closed"
- Playbook Effectiveness is empty
- Primary Playbook is not empty
```

#### Actions
```
Add comment:
---
📊 **Playbook Effectiveness Survey**

Please rate the effectiveness of the playbook used:
**Playbook**: {{Primary Playbook}}

Rate from 1-5:
- 5: Excellent (Very helpful, complete guidance)
- 4: Good (Helpful, minor gaps)
- 3: Adequate (Somewhat helpful, needs improvement)
- 2: Poor (Not very helpful, significant gaps)
- 1: Ineffective (Did not help, major issues)

Update the "Playbook Effectiveness" field before final closure.
---

Send email reminder to {{Assignee}}
Wait 24 hours
IF Playbook Effectiveness still empty:
  Send reminder to SOC Manager
```

---

### RULE 8: Knowledge Base Auto-Linking

**Rule Name**: `AUTO-008: Auto-Link Related KB Articles`
**Trigger**: MITRE ATT&CK Technique added OR Use Case changed
**Scope**: All

#### Lookup Logic
```
Lookup table: attack_technique_to_kb.csv

T1098 → KB-0001 (Admin Group Modification)
T1003.001 → KB-0042 (Credential Dumping Response)
T1110 → KB-0031 (Brute Force Response)
T1021 → KB-0045 (Lateral Movement Response)
T1041 → KB-0051 (Data Exfiltration Response)
```

#### Actions
```
FOR EACH MITRE ATT&CK Technique:
  Look up related KB articles
  Append to "Knowledge Base References" field

Add comment:
📚 **Related Knowledge Base Articles**
{{Knowledge Base References}}

Review these playbooks for guidance.
```

---

## Automation Rule Export/Import

### Export Format (JSON)
```json
{
  "rules": [
    {
      "name": "AUTO-001: Alert Ingestion and Initial Enrichment",
      "trigger": {
        "type": "issue.created",
        "filter": "issueType = Alert"
      },
      "conditions": [
        {
          "field": "summary",
          "operator": "matches",
          "value": "UC-[0-9]{3}"
        }
      ],
      "actions": [
        {
          "type": "set.field",
          "field": "PICERL Phase",
          "value": "Identification"
        }
      ]
    }
  ]
}
```

### Import Instructions
1. Go to Project Settings → Automation
2. Click "Import rules"
3. Upload JSON file
4. Map custom fields to your project
5. Test with sample alert
6. Enable rules

## Testing Checklist

- [ ] Create test alert via webhook
- [ ] Verify all custom fields populated correctly
- [ ] Check assignment logic
- [ ] Validate SLA calculation
- [ ] Test phase transitions
- [ ] Verify sub-task creation
- [ ] Check notification delivery
- [ ] Test escalation scenarios
- [ ] Validate KB linking
- [ ] Review automation audit log

## Monitoring & Maintenance

### Weekly
- Review automation audit log for failures
- Check false assignments
- Monitor SLA breach rate

### Monthly
- Update assignment rotation
- Refresh lookup tables
- Optimize rule performance
- Review and archive old rules

### Quarterly
- Full automation review
- Update mappings (ATT&CK, KB, Use Cases)
- Test all escalation scenarios
- Optimize rule conditions

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: JIRA Administrators & SOC Engineering
