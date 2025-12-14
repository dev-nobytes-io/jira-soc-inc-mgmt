# JIRA Automation Rules for SOC

## Overview

This document contains pre-configured automation rules for SOC incident management in JIRA. These rules automate common tasks, enforce processes, and ensure timely response.

## Automation Rules Index

1. [Auto-Assignment by Category](#1-auto-assignment-by-category)
2. [Severity-Based SLA Alerts](#2-severity-based-sla-alerts)
3. [Auto-Escalation on Age](#3-auto-escalation-on-age)
4. [False Positive Cleanup](#4-false-positive-cleanup)
5. [Stakeholder Notifications](#5-stakeholder-notifications)
6. [Evidence Collection Reminder](#6-evidence-collection-reminder)
7. [Post-Incident Review Trigger](#7-post-incident-review-trigger)
8. [Duplicate Detection](#8-duplicate-detection)
9. [SLA Breach Escalation](#9-sla-breach-escalation)
10. [Auto-Tag MITRE Techniques](#10-auto-tag-mitre-techniques)

---

## How to Import Rules

### Method 1: Manual Creation (Recommended)

1. Navigate to **Project Settings** → **Automation**
2. Click **Create Rule**
3. Follow configurations below for each rule
4. Test each rule before enabling

### Method 2: JSON Import (if available)

1. Copy JSON configuration
2. Navigate to **Automation** → **Create Rule** → **Import**
3. Paste JSON and save

---

## 1. Auto-Assignment by Category

**Purpose**: Automatically assign incidents to appropriate team based on category

**Trigger**: Issue Created or Issue Updated (when Incident Category changes)

**Conditions**:
- Issue Type = Alert OR Incident
- Incident Category is not empty

**Actions**:

```
IF Incident Category = "Malware/Ransomware"
  → Assign to: [Malware Response Team]
  → Add label: "malware"

ELSE IF Incident Category = "Phishing/Social Engineering"
  → Assign to: [Phishing Response Team]
  → Add label: "phishing"

ELSE IF Incident Category = "Compromised Account"
  → Assign to: [Identity Team]
  → Add label: "account-compromise"

ELSE IF Incident Category = "Data Exfiltration/Loss"
  → Assign to: [DLP Team]
  → Add label: "data-loss"

ELSE IF Incident Category = "Insider Threat"
  → Assign to: [Insider Threat Team]
  → Set Assignee Team: "Tier 3 - Advanced Response"

ELSE IF Incident Category = "Vulnerability/Exploit"
  → Assign to: [Vulnerability Management]
  → Add label: "vuln-mgmt"

ELSE
  → Assign to: [SOC Lead]
  → Add comment: "Manual assignment required for category: {{issue.Incident Category}}"
```

**Configuration Steps**:

1. Trigger: Issue created + Issue field value changed (Incident Category)
2. Condition: Issue Type = Alert or Incident
3. Action: Branch rule → Create branches for each category
4. For each branch: Set assignee + Add label
5. Else branch: Assign to SOC Lead

**Test Scenario**:
- Create Alert with Category = "Phishing"
- Verify auto-assignment to Phishing team
- Verify label "phishing" added

---

## 2. Severity-Based SLA Alerts

**Purpose**: Send notifications when issues are approaching SLA breach

**Trigger**: Scheduled (runs every 15 minutes)

**Conditions**:
- Issue Type = Alert or Incident
- Status != Closed
- Time to resolution SLA at risk

**Actions**:

```
IF Incident Severity = "Critical (P1)" AND Time in status > 15 minutes
  → Send email to: SOC Lead, Assigned Team Lead
  → Send Slack message: #soc-critical
  → Add comment: "⚠️ CRITICAL SLA WARNING: Issue open for {{issue.timeInCurrentStatus}}"

ELSE IF Incident Severity = "High (P2)" AND Time in status > 1 hour
  → Send email to: Assignee, SOC Lead
  → Add comment: "⚠️ HIGH SLA WARNING: Issue open for {{issue.timeInCurrentStatus}}"

ELSE IF Incident Severity = "Medium (P3)" AND Time in status > 4 hours
  → Send email to: Assignee
  → Add comment: "SLA approaching: {{issue.timeInCurrentStatus}} in current status"
```

**SLA Thresholds**:
- Critical (P1): 30 minutes to response, 4 hours to resolution
- High (P2): 2 hours to response, 24 hours to resolution
- Medium (P3): 8 hours to response, 72 hours to resolution
- Low (P4): 24 hours to response, 7 days to resolution

**Configuration Steps**:

1. Trigger: Scheduled (every 15 minutes)
2. Condition: Status != Closed
3. Branch by Incident Severity
4. For each severity: Check time in status
5. Send appropriate notifications

---

## 3. Auto-Escalation on Age

**Purpose**: Automatically escalate stale incidents

**Trigger**: Scheduled (runs every hour)

**Conditions**:
- Issue Type = Alert or Incident
- Status = Triage or Investigation
- Updated < 24 hours ago

**Actions**:

```
IF Status = "Triage" AND Time in status > 24 hours
  → Add comment: "🚨 Auto-escalation: No activity for 24 hours in Triage"
  → Transition to: Investigation
  → Send notification to: Assignee, SOC Lead

IF Status = "Investigation" AND Time in status > 48 hours
  → Increase Priority by 1 level
  → Add comment: "🚨 Auto-escalation: Investigation stalled for 48 hours"
  → Assign to: SOC Lead
  → Send notification to: Management
```

**Configuration Steps**:

1. Trigger: Scheduled (every hour)
2. Condition: Issue Type + Status check
3. Branch by Status
4. Check time in status
5. Transition/escalate as needed

---

## 4. False Positive Cleanup

**Purpose**: Automatically close false positive alerts and update detection rules

**Trigger**: Issue Transitioned to "False Positive"

**Conditions**:
- Issue Type = Alert
- Status changed to "False Positive"
- False Positive Reason is not empty

**Actions**:

```
1. Add comment:
   "False Positive Details:
   Reason: {{issue.False Positive Reason}}
   Detection Source: {{issue.Detection Source}}
   Marked by: {{issue.assignee}}"

2. Create linked issue:
   Type: Task (in Detection Engineering project)
   Summary: "Review detection rule: {{issue.summary}}"
   Description: "False positive identified - review and tune detection"
   Link Type: "Caused by"

3. Transition to: Closed

4. Add label: "false-positive"

5. Update custom field: "Closure Reason" = "False Positive"

6. Send notification to: Detection Engineering team
```

**Configuration Steps**:

1. Trigger: Status changed to "False Positive"
2. Condition: False Positive Reason is not empty
3. Add comment with details
4. Create linked tuning task
5. Transition to Closed
6. Notify detection team

---

## 5. Stakeholder Notifications

**Purpose**: Notify stakeholders based on severity and category

**Trigger**: Issue Created or Severity Increased

**Conditions**:
- Issue Type = Incident
- Specific severity/category combinations

**Actions**:

```
IF Severity = "Critical" OR (Severity = "High" AND Category = "Data Exfiltration")
  → Send email to: CISO, Security Director, SOC Lead
  → Send Slack to: #security-leadership
  → Set Communication Status: "Management Briefed"

IF Category = "Data Exfiltration" OR Category = "Insider Threat"
  → Send email to: Data Protection Officer, Legal
  → Add watchers: Compliance Team
  → Set Communication Status: "Stakeholders Notified"

IF Detection Source = "User Report"
  → Send email to: Reporter
  → Add comment: "Thank you for reporting. Our team is investigating."
  → Set Communication Status: "Reporter Acknowledged"
```

**Configuration Steps**:

1. Trigger: Issue created + Field value changed (Severity)
2. Branch by Severity and Category
3. Send appropriate notifications
4. Update Communication Status

---

## 6. Evidence Collection Reminder

**Purpose**: Remind analysts to collect and preserve evidence

**Trigger**: Issue Transitioned to "Investigation" or "Containment"

**Conditions**:
- Issue Type = Incident
- Evidence Links field is empty

**Actions**:

```
1. Add comment:
   "📋 EVIDENCE COLLECTION CHECKLIST

   Please collect and link the following evidence:
   - [ ] System logs (Event Viewer, Syslog)
   - [ ] Network traffic captures (PCAP)
   - [ ] Memory dumps (if applicable)
   - [ ] Disk images (if applicable)
   - [ ] Screenshots of indicators
   - [ ] SIEM/EDR alert details
   - [ ] User interview notes

   Upload to evidence server and add links to 'Evidence Links' field"

2. Set due date: +4 hours from transition

3. Create subtask:
   Summary: "Collect and document evidence for {{issue.key}}"
   Assignee: {{issue.assignee}}
   Due: +4 hours
```

**Configuration Steps**:

1. Trigger: Status changed to Investigation or Containment
2. Condition: Evidence Links is empty
3. Add checklist comment
4. Create evidence collection subtask

---

## 7. Post-Incident Review Trigger

**Purpose**: Automatically create PIR page in Confluence when incident closed

**Trigger**: Issue Transitioned to "Closed"

**Conditions**:
- Issue Type = Incident
- Severity = Critical or High
- Status changed to Closed

**Actions**:

```
1. Create Confluence page:
   Space: SOC Operations
   Parent: "Post-Incident Reviews / {{issue.created.format('YYYY')}}"
   Title: "PIR - {{issue.key}} - {{issue.summary}}"
   Template: "Post-Incident Review Template"

   Page content populated with:
   - Incident summary: {{issue.summary}}
   - Severity: {{issue.Incident Severity}}
   - Category: {{issue.Incident Category}}
   - Duration: {{issue.created}} to {{now}}
   - Affected Assets: {{issue.Affected Assets}}
   - Response Actions: {{issue.Response Actions}}
   - Root Cause: {{issue.Root Cause}}

2. Add remote link to JIRA issue

3. Add comment to JIRA:
   "📝 Post-Incident Review page created: [View PIR](link)"

4. Assign PIR task to: SOC Lead

5. Send notification to: Incident response team, Management
```

**Configuration Steps**:

1. Trigger: Status changed to Closed
2. Condition: Issue Type = Incident AND Severity = Critical/High
3. Create Confluence page via REST API
4. Link page to issue
5. Notify stakeholders

---

## 8. Duplicate Detection

**Purpose**: Identify and link potential duplicate incidents

**Trigger**: Issue Created

**Conditions**:
- Issue Type = Alert or Incident

**Actions**:

```
1. Search for similar issues:
   JQL: project = SOC
        AND status != Closed
        AND "Incident Category" = "{{issue.Incident Category}}"
        AND "Affected Assets" ~ "{{issue.Affected Assets}}"
        AND created >= -7d

2. IF similar issues found (>0):
   → Add comment: "⚠️ Potential duplicates found: {{foundIssues.key}}"
   → Link issues with "Relates to" link type
   → Send notification to: Assignee
   → Add label: "potential-duplicate"

3. IF similar issues found (>2):
   → Add comment: "🚨 Multiple similar incidents - possible campaign"
   → Add label: "campaign"
   → Assign to: Threat Intelligence team
```

**Configuration Steps**:

1. Trigger: Issue created
2. Action: Lookup issues with JQL
3. Condition: If issues found
4. Link issues and notify
5. Special handling for campaigns

---

## 9. SLA Breach Escalation

**Purpose**: Escalate when SLA is breached

**Trigger**: SLA Breached (if available) or Scheduled check

**Conditions**:
- Issue Type = Alert or Incident
- SLA time exceeded

**Actions**:

```
1. Increase Priority:
   Medium → High
   High → Critical

2. Assign to: SOC Lead (if not already)

3. Add comment:
   "🚨 SLA BREACH DETECTED

   Expected Resolution: {{issue.sla.expectedTime}}
   Actual Time: {{now}}
   Breach Duration: {{breach.duration}}

   Escalating to SOC Lead for immediate attention."

4. Send notifications:
   → Email: SOC Lead, CISO (for Critical)
   → Slack: #soc-critical

5. Add label: "sla-breach"

6. Create linked issue:
   Type: Task
   Summary: "SLA Breach Review - {{issue.key}}"
   Assign to: SOC Lead
   Description: "Investigate why SLA was breached and document lessons learned"
```

**Configuration Steps**:

1. Trigger: Scheduled (every 15 min) or SLA trigger
2. Condition: Check time vs SLA threshold
3. Escalate priority
4. Reassign and notify
5. Create review task

---

## 10. Auto-Tag MITRE Techniques

**Purpose**: Automatically suggest MITRE ATT&CK techniques based on incident details

**Trigger**: Issue Updated (Description or IOCs field changed)

**Conditions**:
- Issue Type = Incident
- MITRE ATT&CK Techniques field is empty

**Actions**:

```
1. Analyze description and IOCs for keywords:

   IF description contains "credential dump" OR "mimikatz" OR "lsass"
     → Suggest: T1003 - OS Credential Dumping

   IF description contains "powershell" AND "encoded" OR "bypass"
     → Suggest: T1059.001 - PowerShell
     → Suggest: T1140 - Deobfuscate/Decode Files

   IF description contains "scheduled task" OR "at.exe"
     → Suggest: T1053 - Scheduled Task/Job

   IF description contains "rdp" OR "remote desktop"
     → Suggest: T1021.001 - Remote Desktop Protocol

   IF IOCs contains domain OR IP addresses (non-RFC1918)
     → Suggest: T1071 - Application Layer Protocol
     → Suggest: T1095 - Non-Application Layer Protocol

2. Add comment with suggestions:
   "🎯 MITRE ATT&CK Technique Suggestions:

   Based on incident description, consider mapping:
   - T1003 - OS Credential Dumping
   - T1059.001 - PowerShell

   Review and update 'MITRE ATT&CK Techniques' field if appropriate."

3. Add label: "mitre-suggested"
```

**Configuration Steps**:

1. Trigger: Issue updated (Description or IOCs)
2. Condition: MITRE field is empty
3. Use smart value conditions to detect keywords
4. Add comment with suggestions
5. Tag for analyst review

---

## Testing Automation Rules

### Test Checklist

For each rule:

- [ ] Create test issue matching trigger conditions
- [ ] Verify rule triggers correctly
- [ ] Check all actions execute
- [ ] Verify notifications sent
- [ ] Validate field updates
- [ ] Test edge cases
- [ ] Review audit log

### Test Environment Setup

1. Create test project or use sandbox
2. Configure identical custom fields
3. Use test user accounts
4. Set up test notification channels
5. Import automation rules

### Common Issues & Solutions

**Rule not triggering**:
- Check rule is enabled
- Verify trigger conditions
- Check project scope
- Review audit log

**Actions not executing**:
- Verify permissions
- Check field availability
- Validate action configuration
- Test with simpler action first

**Notifications not sent**:
- Verify email/Slack configuration
- Check user notification preferences
- Test notification channel separately

---

## Best Practices

1. **Start Simple**: Enable one rule at a time
2. **Test Thoroughly**: Use test issues before production
3. **Monitor Audit Logs**: Review regularly for issues
4. **Document Changes**: Track rule modifications
5. **Get Feedback**: Collect analyst input on effectiveness
6. **Iterate**: Refine rules based on real usage
7. **Avoid Loops**: Be careful with rules that trigger on field changes
8. **Use Labels**: Tag automated actions for tracking

---

## Rule Maintenance

### Weekly
- Review automation audit log
- Check for failed executions
- Verify notifications delivered

### Monthly
- Analyze rule effectiveness
- Gather team feedback
- Optimize trigger conditions
- Update notification lists

### Quarterly
- Full rule review
- Remove unused rules
- Update based on new use cases
- Document changes

---

## Advanced Automation Ideas

### Future Enhancements

1. **Automated Enrichment**: Query threat intel APIs
2. **Asset Correlation**: Auto-populate asset details from CMDB
3. **Similar Incident Linking**: ML-based duplicate detection
4. **Playbook Selection**: Auto-attach appropriate playbook
5. **Time-based Assignment**: Assign based on on-call schedule
6. **Metrics Collection**: Auto-populate metrics for reporting
7. **Integration Triggers**: Trigger actions in external systems
8. **Smart Prioritization**: Adjust priority based on multiple factors

---

## Automation JSON Templates

### Template: Basic Auto-Assignment

```json
{
  "trigger": {
    "type": "field-value-changed",
    "field": "Incident Category"
  },
  "conditions": [
    {
      "type": "issue-type",
      "value": ["Alert", "Incident"]
    }
  ],
  "actions": [
    {
      "type": "branch",
      "branches": [
        {
          "condition": {
            "field": "Incident Category",
            "equals": "Phishing/Social Engineering"
          },
          "actions": [
            {
              "type": "assign",
              "assignee": "phishing-team"
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Support

For questions or issues with automation:
- Review JIRA automation documentation
- Check audit logs for error details
- Contact: SOC Team Lead or JIRA Administrator

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Operations Team
