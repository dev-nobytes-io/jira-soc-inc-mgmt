# JIRA Setup Guide for SOC Case Management

## Overview

This guide walks through the complete setup of JIRA for SOC incident management, from project creation through automation configuration.

**Estimated Setup Time**: 60-90 minutes
**Required Permissions**: JIRA Administrator

## Table of Contents

1. [Project Creation](#project-creation)
2. [Custom Fields](#custom-fields)
3. [Issue Types](#issue-types)
4. [Workflows](#workflows)
5. [Screens](#screens)
6. [Permission Scheme](#permission-scheme)
7. [Notification Scheme](#notification-scheme)
8. [Dashboards](#dashboards)
9. [Automation Rules](#automation-rules)
10. [Testing](#testing)

---

## Project Creation

### Step 1: Create New Project

1. Navigate to **Projects** → **Create Project**
2. Select project template: **Kanban** or **Scrum** (recommend Kanban for SOC)
3. Project details:
   - **Name**: SOC Operations
   - **Key**: SOC
   - **Project Type**: Team-managed (for simplicity) or Company-managed (for advanced workflows)
   - **Lead**: [SOC Team Lead]

### Step 2: Project Settings

Configure basic project settings:

```
Project Settings → Details
- Description: Security Operations Center incident management and tracking
- Category: Security
- Avatar: [Security icon]
```

---

## Custom Fields

Create custom fields to track incident-specific information.

### Navigate to Custom Fields

**Path**: Settings (⚙️) → Issues → Custom Fields → Create Custom Field

### Field Definitions

#### 1. Incident Severity
- **Type**: Select List (single choice)
- **Name**: Incident Severity
- **Description**: Impact and urgency of the security incident
- **Options**:
  - 🔴 Critical (P1)
  - 🟠 High (P2)
  - 🟡 Medium (P3)
  - 🟢 Low (P4)
  - ⚪ Informational (P5)
- **Default**: Medium (P3)
- **Required**: Yes

#### 2. Incident Category
- **Type**: Select List (single choice)
- **Name**: Incident Category
- **Description**: Type of security incident
- **Options**:
  - Malware/Ransomware
  - Phishing/Social Engineering
  - Compromised Account
  - Data Exfiltration/Loss
  - Insider Threat
  - Unauthorized Access
  - Denial of Service
  - Policy Violation
  - Vulnerability/Exploit
  - Other
- **Required**: Yes

#### 3. Affected Assets
- **Type**: Labels or Multi-line Text
- **Name**: Affected Assets
- **Description**: Systems, users, or resources impacted
- **Required**: No

#### 4. Detection Source
- **Type**: Select List (single choice)
- **Name**: Detection Source
- **Description**: How the incident was detected
- **Options**:
  - SIEM Alert
  - EDR/XDR
  - Email Security Gateway
  - Firewall/IDS/IPS
  - User Report
  - Threat Intelligence
  - Vulnerability Scanner
  - Manual Discovery
  - Third-Party Notification
- **Required**: Yes

#### 5. Indicators of Compromise (IOCs)
- **Type**: Multi-line Text
- **Name**: Indicators of Compromise
- **Description**: IPs, domains, hashes, file paths, etc.
- **Required**: No

#### 6. MITRE ATT&CK Tactics
- **Type**: Select List (multiple choice)
- **Name**: MITRE ATT&CK Tactics
- **Description**: Adversary tactics observed
- **Options**:
  - Initial Access
  - Execution
  - Persistence
  - Privilege Escalation
  - Defense Evasion
  - Credential Access
  - Discovery
  - Lateral Movement
  - Collection
  - Command and Control
  - Exfiltration
  - Impact
- **Required**: No

#### 7. MITRE ATT&CK Techniques
- **Type**: Multi-line Text
- **Name**: MITRE ATT&CK Techniques
- **Description**: Specific technique IDs (e.g., T1566.001)
- **Required**: No

#### 8. Response Actions
- **Type**: Multi-line Text
- **Name**: Response Actions
- **Description**: Actions taken to respond to incident
- **Required**: No

#### 9. Root Cause
- **Type**: Multi-line Text
- **Name**: Root Cause
- **Description**: Identified root cause of incident
- **Required**: No (required for closure)

#### 10. Evidence Links
- **Type**: URL or Multi-line Text
- **Name**: Evidence Links
- **Description**: Links to evidence (logs, screenshots, artifacts)
- **Required**: No

#### 11. Assigned Team
- **Type**: Select List (single choice)
- **Name**: Assigned Team
- **Description**: SOC team responsible for handling
- **Options**:
  - Tier 1 - Monitoring
  - Tier 2 - Investigation
  - Tier 3 - Advanced Response
  - Incident Response Team
  - Threat Intelligence
  - Forensics
- **Required**: No

#### 12. Communication Status
- **Type**: Select List (single choice)
- **Name**: Communication Status
- **Description**: External communication status
- **Options**:
  - No Communication Needed
  - Stakeholders Notified
  - Management Briefed
  - Customer Notified
  - Regulatory Notification Required
- **Required**: No

#### 13. False Positive Reason
- **Type**: Select List (single choice)
- **Name**: False Positive Reason
- **Description**: Why alert was false positive
- **Options**:
  - Authorized Activity
  - Misconfiguration
  - Detection Rule Issue
  - Testing/Simulation
  - Duplicate Alert
  - Other
- **Required**: No (only for false positives)

---

## Issue Types

### Create Custom Issue Types

**Path**: Settings (⚙️) → Issues → Issue Types → Add Issue Type

### Issue Type Definitions

#### 1. Alert
- **Name**: Alert
- **Description**: Automated security alert from detection systems
- **Icon**: 🚨 (Alert icon)
- **Type**: Standard

**Typical Fields**:
- Detection Source
- Incident Severity
- Incident Category
- Affected Assets
- IOCs

#### 2. Incident
- **Name**: Incident
- **Description**: Confirmed security incident requiring response
- **Icon**: 🔥 (Fire icon)
- **Type**: Standard

**Typical Fields**:
- All alert fields plus:
- Response Actions
- Root Cause
- Communication Status
- MITRE ATT&CK mapping

#### 3. Investigation
- **Name**: Investigation
- **Description**: Proactive threat hunting or research activity
- **Icon**: 🔍 (Magnifying glass icon)
- **Type**: Standard

#### 4. Policy Violation
- **Name**: Policy Violation
- **Description**: Security policy or compliance violation
- **Icon**: ⚠️ (Warning icon)
- **Type**: Standard

#### 5. Vulnerability
- **Name**: Vulnerability
- **Description**: Identified security weakness requiring remediation
- **Icon**: 🛡️ (Shield icon)
- **Type**: Standard

### Associate Issue Types with Project

1. Go to **Project Settings** → **Issue Types**
2. Add all created issue types to SOC project
3. Set **Alert** as default issue type

---

## Workflows

### Alert Workflow

Create workflow for automated alerts:

**States**:
1. **New** → Initial state for new alerts
2. **Triage** → Analyst reviewing alert
3. **Investigation** → Active investigation
4. **Escalated** → Promoted to Incident
5. **False Positive** → Determined benign
6. **Closed** → Final state

**Transitions**:
- New → Triage (Start Triage)
- Triage → Investigation (Investigate)
- Triage → False Positive (Mark False Positive)
- Investigation → Escalated (Escalate to Incident)
- Investigation → False Positive (Mark False Positive)
- False Positive → Closed (Close)
- Escalated → Closed (Close)

**Workflow Configuration**:

```
1. Settings → Issues → Workflows → Add Workflow
2. Name: Alert Workflow
3. Add states and transitions as above
4. Configure transition screens:
   - Mark False Positive: Require "False Positive Reason"
   - Close: Require comments
```

### Incident Workflow

**States**:
1. **New**
2. **Triage**
3. **Investigation**
4. **Containment**
5. **Eradication**
6. **Recovery**
7. **Post-Incident**
8. **Closed**

**Transitions**:
- New → Triage
- Triage → Investigation
- Investigation → Containment
- Containment → Eradication
- Eradication → Recovery
- Recovery → Post-Incident
- Post-Incident → Closed
- Any → Triage (Reopen)

### Investigation Workflow

**States**:
1. **New**
2. **In Progress**
3. **Analysis**
4. **Report**
5. **Closed**

---

## Screens

Create custom screens for each issue type to show relevant fields.

### Alert Screen Configuration

**Path**: Settings → Issues → Screens

**Create Screen**: "Alert Screen"

**Fields to Include**:
- Summary
- Description
- Detection Source
- Incident Severity
- Incident Category
- Affected Assets
- Indicators of Compromise
- Assignee
- Reporter
- Priority
- Labels

### Incident Screen Configuration

**Create Screen**: "Incident Screen"

**Fields to Include** (all Alert fields plus):
- Response Actions
- MITRE ATT&CK Tactics
- MITRE ATT&CK Techniques
- Root Cause
- Evidence Links
- Communication Status
- Assigned Team

### Associate Screens with Issue Types

1. **Settings** → **Issues** → **Screen Schemes**
2. Create scheme for each issue type
3. Map screens to operations (Create, Edit, View)

---

## Permission Scheme

### Create SOC Permission Scheme

**Path**: Settings → Issues → Permission Schemes → Add Permission Scheme

**Scheme Name**: SOC Operations Permissions

### Permission Configuration

| Permission | Role/Group |
|------------|------------|
| **Browse Projects** | SOC Team, Security Team, Management |
| **Create Issues** | SOC Team, All Users (for reporting) |
| **Edit Issues** | SOC Team (own issues), SOC Leads (all) |
| **Assign Issues** | SOC Team |
| **Assignable User** | SOC Team, Incident Response Team |
| **Delete Issues** | SOC Leads only |
| **Close Issues** | SOC Team |
| **Transition Issues** | SOC Team |
| **Add Comments** | SOC Team, Security Team |
| **Delete Comments** | Comment Author, SOC Leads |
| **Manage Watchers** | SOC Team |
| **View Voters and Watchers** | SOC Team, Security Team |

### Apply Permission Scheme

1. Go to **Project Settings** → **Permissions**
2. Select "SOC Operations Permissions"
3. Save

---

## Notification Scheme

### Create Notification Scheme

**Path**: Settings → System → Notification Schemes → Add Notification Scheme

**Scheme Name**: SOC Notifications

### Events and Recipients

| Event | Notify |
|-------|--------|
| **Issue Created** | Reporter, Assignee, SOC Leads |
| **Issue Updated** | Assignee, Watchers |
| **Issue Assigned** | Current Assignee, Previous Assignee |
| **Work Started** | Assignee, Watchers |
| **Issue Resolved** | Reporter, Assignee, SOC Leads |
| **Issue Closed** | Reporter, Assignee |
| **Issue Commented** | Assignee, Watchers, Comment Author |
| **Issue Reopened** | SOC Leads, Previous Assignee |
| **Priority Changed** | Assignee, SOC Leads (if escalated) |

### Apply Notification Scheme

1. **Project Settings** → **Notifications**
2. Select "SOC Notifications"

---

## Dashboards

### Create SOC Dashboard

**Path**: Dashboards → Create Dashboard

**Dashboard Name**: SOC Operations Dashboard

### Recommended Gadgets

#### 1. Filter Results
- **Filter**: All Open Incidents
- **Columns**: Key, Summary, Severity, Status, Assignee, Created

#### 2. Pie Chart - Incidents by Severity
- **Filter**: Open Incidents
- **Statistic**: Incident Severity

#### 3. Pie Chart - Incidents by Category
- **Filter**: Last 30 days
- **Statistic**: Incident Category

#### 4. Created vs Resolved Chart
- **Filter**: All Incidents
- **Time period**: Last 30 days

#### 5. Two Dimensional Filter Statistics
- **Filter**: Open Incidents
- **X-Axis**: Incident Category
- **Y-Axis**: Incident Severity

#### 6. Activity Stream
- **Filter**: Recent Activity (Last 7 days)

#### 7. Average Age Chart
- **Filter**: Open Incidents
- **Grouped by**: Incident Severity

### Example Dashboard Layout

```
┌─────────────────────────────────────────────────┐
│            SOC Operations Dashboard              │
├──────────────────┬──────────────────────────────┤
│  Open Incidents  │  Incidents by Severity       │
│  (Filter)        │  (Pie Chart)                 │
├──────────────────┼──────────────────────────────┤
│  Incidents by    │  Created vs Resolved         │
│  Category (Pie)  │  (Line Chart)                │
├──────────────────┴──────────────────────────────┤
│  Incident Matrix (Category × Severity)          │
│  (Two-Dimensional Statistics)                   │
├─────────────────────────────────────────────────┤
│  Recent Activity Stream                         │
└─────────────────────────────────────────────────┘
```

---

## Automation Rules

See [automation/jira-rules/README.md](../../automation/jira-rules/README.md) for detailed automation configurations.

### Quick Setup - Essential Rules

1. **Auto-assign by category**
2. **SLA notifications**
3. **Severity escalation**
4. **False positive cleanup**
5. **Stakeholder notifications**

---

## Testing

### Test Checklist

- [ ] Create test Alert issue
- [ ] Verify all custom fields visible
- [ ] Test workflow transitions
- [ ] Verify notifications sent
- [ ] Test escalation from Alert → Incident
- [ ] Test false positive workflow
- [ ] Verify dashboard displays correctly
- [ ] Test automation rules
- [ ] Verify permissions work correctly
- [ ] Create test incident and close it

### Test Scenarios

#### Scenario 1: New Alert
1. Create Alert issue via API/webhook simulation
2. Verify auto-assignment
3. Move through workflow states
4. Mark as false positive
5. Verify closure

#### Scenario 2: Incident Response
1. Create or escalate to Incident
2. Progress through all workflow states
3. Add evidence and response actions
4. Complete post-incident review
5. Close incident

#### Scenario 3: Permission Testing
1. Test as SOC Analyst
2. Test as SOC Lead
3. Test as Read-Only user
4. Verify appropriate access levels

---

## Post-Setup Tasks

### 1. Team Training
- [ ] Walk through JIRA interface
- [ ] Demonstrate workflows
- [ ] Practice creating and updating tickets
- [ ] Review dashboard usage

### 2. Integration Setup
- [ ] Configure SIEM webhook
- [ ] Test alert creation
- [ ] Set up Slack/Teams notifications
- [ ] Link to Confluence

### 3. Documentation
- [ ] Create quick reference guide
- [ ] Document custom processes
- [ ] Update playbooks with JIRA references

### 4. Optimization
- [ ] Gather team feedback
- [ ] Adjust workflows as needed
- [ ] Tune automation rules
- [ ] Refine dashboards

---

## Troubleshooting

### Issue: Custom Fields Not Showing
**Solution**:
- Check field context configuration
- Verify field is added to appropriate screens
- Check issue type associations

### Issue: Automation Not Triggering
**Solution**:
- Review automation audit log
- Check rule conditions
- Verify project scope
- Check for conflicting rules

### Issue: Notifications Not Sent
**Solution**:
- Verify notification scheme applied
- Check user email settings
- Review notification configuration
- Check spam filters

### Issue: Workflow Transition Missing
**Solution**:
- Verify workflow applied to issue type
- Check transition conditions
- Verify user permissions
- Review workflow scheme

---

## Maintenance

### Weekly
- Review automation audit logs
- Check for stuck issues
- Monitor dashboard metrics

### Monthly
- Clean up old false positives
- Review and update custom fields
- Optimize automation rules
- Update dashboards

### Quarterly
- Full workflow review
- Permission scheme audit
- Dashboard effectiveness review
- User feedback session

---

## Next Steps

After JIRA setup is complete:

1. [Configure Confluence](../confluence/SETUP.md)
2. [Set up Integrations](../../integrations/README.md)
3. [Deploy Automation Rules](../../automation/jira-rules/README.md)
4. [Create Playbooks](../../playbooks/README.md)

---

**Setup Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Team Lead
