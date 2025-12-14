# JIRA Configuration Items Integration Guide

## Overview

This guide provides comprehensive instructions for configuring JIRA custom fields to support Configuration Items (CI), framework mappings (NIST CSF 2.0, PICERL, MITRE ATT&CK, RE&CT, DeTT&CT), and knowledge base integration.

## Table of Contents

1. [Configuration Items Fields](#configuration-items-fields)
2. [Detection Analytics Fields](#detection-analytics-fields)
3. [MITRE ATT&CK Fields](#mitre-attck-fields)
4. [Framework Fields](#framework-fields)
5. [Knowledge Base Fields](#knowledge-base-fields)
6. [Automation Configuration](#automation-configuration)
7. [Dashboard Setup](#dashboard-setup)

---

## Configuration Items Fields

### Field 1: Detection Analytics
**Purpose**: Link incidents to detection rules that identified them

**Configuration**:
- **Field Name**: Detection Analytics
- **Type**: Labels or Multi-line text
- **Format**: `ANALYTIC-{3-digit-ID}`
- **Example**: `ANALYTIC-001`, `ANALYTIC-042`
- **Required**: No (recommended for Alert and Incident types)
- **Searchable**: Yes

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Labels" or "Multi-line text"
2. Name: "Detection Analytics"
3. Description: "Detection rules that identified this incident (e.g., ANALYTIC-001)"
4. Associate with screens: Alert screen, Incident screen
5. Add to workflows: All incident types
```

**Usage**:
- Populated automatically via SIEM webhook
- Links to detection analytics repository
- Enables detection effectiveness tracking

---

### Field 2: DeTT&CT Coverage ID
**Purpose**: Link incidents to detection coverage assessments

**Configuration**:
- **Field Name**: DeTT&CT Coverage
- **Type**: Labels
- **Format**: `DETTCT-{ID}` or `Coverage-{Date}`
- **Example**: `DETTCT-Q4-2025`, `Coverage-2025-12`
- **Required**: No
- **Searchable**: Yes

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Labels"
2. Name: "DeTT&CT Coverage"
3. Description: "Detection coverage assessment reference"
4. Associate with screens: All issue types
```

---

## Detection Analytics Fields

### Field 3: Detection Source (Enhanced)
**Purpose**: Specify which tool/platform detected the incident

**Configuration**:
- **Field Name**: Detection Source
- **Type**: Single-select dropdown
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
  - Cloud Security Posture Management (CSPM)
  - Data Loss Prevention (DLP)
  - User Behavior Analytics (UBA)
- **Required**: Yes (for Alert and Incident types)
- **Default**: None

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Select List (single choice)"
2. Name: "Detection Source"
3. Description: "System or method that detected this security event"
4. Configure options (list above)
5. Associate with screens: Alert screen, Incident screen
6. Make required for Alert and Incident types
```

---

## MITRE ATT&CK Fields

### Field 4: MITRE ATT&CK Tactics
**Purpose**: High-level adversary objectives

**Configuration**:
- **Field Name**: MITRE ATT&CK Tactics
- **Type**: Multi-select checkboxes
- **Options**:
  - Reconnaissance (TA0043)
  - Resource Development (TA0042)
  - Initial Access (TA0001)
  - Execution (TA0002)
  - Persistence (TA0003)
  - Privilege Escalation (TA0004)
  - Defense Evasion (TA0005)
  - Credential Access (TA0006)
  - Discovery (TA0007)
  - Lateral Movement (TA0008)
  - Collection (TA0009)
  - Command and Control (TA0011)
  - Exfiltration (TA0010)
  - Impact (TA0040)
- **Required**: No (recommended for Incident type)
- **Default**: None

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Checkboxes" or "Multi Select"
2. Name: "MITRE ATT&CK Tactics"
3. Description: "Adversary tactics observed in this incident"
4. Configure options (list above with TA codes)
5. Associate with screens: Incident screen, Investigation screen
```

---

### Field 5: MITRE ATT&CK Techniques
**Purpose**: Specific adversary techniques observed

**Configuration**:
- **Field Name**: MITRE ATT&CK Techniques
- **Type**: Multi-line text or Labels
- **Format**: `T{ID}` or `T{ID}.{Sub-ID}`
- **Example**: `T1003.001`, `T1566.002`, `T1047`
- **Required**: No (recommended for Incident type)
- **Searchable**: Yes

**Create Field**:
```
Settings → Issues → Custom Fields → Custom Field
1. Select Field Type: "Labels" (preferred) or "Multi-line text"
2. Name: "MITRE ATT&CK Techniques"
3. Description: "Specific technique IDs observed (e.g., T1003.001, T1566.002)"
4. Associate with screens: Incident screen, Investigation screen
```

**Usage Tips**:
- Enter T-codes one per line (if multi-line text)
- Use labels for better searchability
- Auto-populate from Detection Analytics
- Link to ATT&CK Navigator

---

### Field 6: ATT&CK Procedure Details
**Purpose**: Detailed description of how techniques were used

**Configuration**:
- **Field Name**: ATT&CK Procedure Details
- **Type**: Multi-line text
- **Required**: No
- **Usage**: Narrative description

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Text Field (multi-line)"
2. Name: "ATT&CK Procedure Details"
3. Description: "Detailed description of adversary procedures observed"
4. Associate with screens: Incident screen
```

---

## Framework Fields

### NIST CSF 2.0 Fields

#### Field 7: NIST CSF Function
**Purpose**: Primary CSF function for incident activity

**Configuration**:
- **Field Name**: NIST CSF Function
- **Type**: Single-select dropdown
- **Options**:
  - Govern (GV)
  - Identify (ID)
  - Protect (PR)
  - Detect (DE)
  - Respond (RS)
  - Recover (RC)
- **Required**: No
- **Default**: Auto-populated based on workflow state

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Select List (single choice)"
2. Name: "NIST CSF Function"
3. Description: "Primary NIST CSF 2.0 function for this activity"
4. Configure options (list above)
5. Associate with all issue types
```

**Auto-population Rule**:
```
Workflow State → CSF Function:
  Triage → Detect (DE)
  Investigation → Detect (DE) / Respond (RS)
  Containment → Respond (RS)
  Eradication → Respond (RS)
  Recovery → Recover (RC)
  Post-Incident → Recover (RC) / Govern (GV)
```

---

#### Field 8: NIST CSF Categories
**Purpose**: Specific CSF categories addressed

**Configuration**:
- **Field Name**: NIST CSF Categories
- **Type**: Multi-line text or Labels
- **Format**: `{Function}.{Category}` (e.g., `DE.AE`, `RS.MI`)
- **Example**: `DE.AE-07`, `RS.MI-01`, `RC.RP-01`
- **Required**: No

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Labels"
2. Name: "NIST CSF Categories"
3. Description: "NIST CSF 2.0 categories (e.g., DE.AE-07, RS.MI-01)"
4. Associate with all issue types
```

---

### PICERL Framework Fields

#### Field 9: PICERL Phase
**Purpose**: Current incident management phase

**Configuration**:
- **Field Name**: PICERL Phase
- **Type**: Single-select dropdown
- **Options**:
  - Preparation
  - Identification
  - Containment
  - Eradication
  - Recovery
  - Lessons Learned
- **Required**: No
- **Default**: Auto-populated based on workflow state

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Select List (single choice)"
2. Name: "PICERL Phase"
3. Description: "Current PICERL incident management phase"
4. Configure options (list above)
5. Associate with Incident, Investigation issue types
```

**Auto-population Rule**:
```
Workflow State → PICERL Phase:
  New, Triage, Investigation → Identification
  Containment → Containment
  Eradication → Eradication
  Recovery → Recovery
  Post-Incident → Lessons Learned
```

---

#### Field 10: PICERL Phase Timestamps
**Purpose**: Track phase transition times

**Configuration**:
- Create multiple Date/Time fields:
  - **Identification Start**: Auto-set when status = New
  - **Containment Start**: Auto-set when status = Containment
  - **Eradication Start**: Auto-set when status = Eradication
  - **Recovery Start**: Auto-set when status = Recovery
  - **Lessons Learned Start**: Auto-set when status = Post-Incident

**Create Fields** (repeat for each phase):
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Date Time Picker"
2. Name: "[Phase] Start Time" (e.g., "Containment Start Time")
3. Description: "Timestamp when [phase] began"
4. Associate with Incident issue type
5. Configure automation to auto-populate on workflow transition
```

---

#### Field 11: PICERL Phase Duration
**Purpose**: Calculate time spent in each phase

**Configuration**:
- Create calculated fields (requires ScriptRunner or similar add-on)
- **Formula**: End time - Start time (in hours)
- **Examples**:
  - Containment Duration = Eradication Start - Containment Start
  - Total Incident Duration = Closed - Created

**Note**: Calculated fields may require JIRA add-ons. Alternative: Calculate in dashboards/reports.

---

### RE&CT Framework Fields

#### Field 12: RE&CT Actions
**Purpose**: Track response actions taken

**Configuration**:
- **Field Name**: RE&CT Actions
- **Type**: Multi-line text or Labels
- **Format**: `RA{4-digit-ID}`
- **Example**: `RA3101`, `RA4201`, `RA6002`
- **Required**: No

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Labels"
2. Name: "RE&CT Actions"
3. Description: "RE&CT response actions performed (e.g., RA3101, RA4201)"
4. Associate with Incident issue type
```

**Auto-population Rule**:
```
Workflow Transition → RE&CT Actions:
  To Containment → Suggest: RA3101, RA3201, RA3301
  To Eradication → Suggest: RA4101, RA4201, RA4401
  To Recovery → Suggest: RA5001, RA5101
  To Post-Incident → Suggest: RA6001, RA6002, RA6003
```

---

## Knowledge Base Fields

### Field 13: Knowledge Base References
**Purpose**: Link relevant KB articles and documentation

**Configuration**:
- **Field Name**: Knowledge Base References
- **Type**: Multi-line text (for multiple URLs) or URL field
- **Format**: KB-{ID} or full Confluence URLs
- **Example**: `KB-0042`, `https://confluence.company.com/...`
- **Required**: No (recommended for closure)

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Text Field (multi-line)" or "URL"
2. Name: "Knowledge Base References"
3. Description: "Links to playbooks, runbooks, and KB articles (KB-XXXX or URLs)"
4. Associate with all issue types
```

---

### Field 14: Primary Playbook
**Purpose**: Main playbook used for incident response

**Configuration**:
- **Field Name**: Primary Playbook
- **Type**: Single-select dropdown or URL
- **Options** (if dropdown):
  - KB-0011: Phishing Response
  - KB-0027: Malware Response
  - KB-0042: Credential Dumping Response
  - KB-0045: Lateral Movement Response
  - KB-0051: Data Exfiltration Response
  - KB-0061: Insider Threat Response
  - KB-0073: Ransomware Response
  - Custom (enter in KB References)
- **Required**: No
- **Default**: Auto-populated based on Incident Category

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Select List (single choice)"
2. Name: "Primary Playbook"
3. Description: "Primary incident response playbook used"
4. Configure options (list above)
5. Associate with Incident issue type
```

**Auto-population Rule**:
```
Incident Category → Primary Playbook:
  Phishing → KB-0011
  Malware/Ransomware → KB-0027
  Compromised Account → KB-0042
  Lateral Movement → KB-0045
  Data Exfiltration/Loss → KB-0051
  Insider Threat → KB-0061
  Ransomware (specific) → KB-0073
```

---

### Field 15: Playbook Effectiveness
**Purpose**: Rate playbook helpfulness

**Configuration**:
- **Field Name**: Playbook Effectiveness
- **Type**: Single-select dropdown
- **Options**:
  - 5 - Excellent (Very helpful, complete guidance)
  - 4 - Good (Helpful, minor gaps)
  - 3 - Adequate (Somewhat helpful, needs improvement)
  - 2 - Poor (Not very helpful, significant gaps)
  - 1 - Ineffective (Did not help, major issues)
  - N/A - Not Used
- **Required**: No (prompt on closure)

**Create Field**:
```
Settings → Issues → Custom Fields → Create Custom Field
1. Select Field Type: "Select List (single choice)"
2. Name: "Playbook Effectiveness"
3. Description: "Rate the effectiveness of the playbook used"
4. Configure options (list above)
5. Associate with Incident issue type
6. Configure automation to prompt for rating on closure
```

---

## Automation Configuration

### Automation Rule 1: Auto-populate Detection Analytics
```
Rule Name: Auto-populate Detection Analytics
Trigger: Issue created (via webhook)
Condition: Alert source contains analytic ID
Actions:
  1. Parse alert name/ID
  2. Extract ANALYTIC-{ID}
  3. Set "Detection Analytics" field
  4. Set "MITRE ATT&CK Techniques" (lookup from analytic metadata)
  5. Add comment: "Detected by: [ANALYTIC-ID]"
```

**Configuration** (JIRA Automation):
```
1. Create rule: When issue created
2. Add condition: IF summary contains "ANALYTIC-"
3. Add action: Set field "Detection Analytics"
   - Use regex: ANALYTIC-\d{3}
4. Add action: Add comment with detection details
```

---

### Automation Rule 2: Auto-populate PICERL Phase
```
Rule Name: Auto-populate PICERL Phase
Trigger: Status changed
Condition: Status in (specific states)
Actions:
  1. Map workflow status to PICERL phase
  2. Set "PICERL Phase" field
  3. Set phase start timestamp
```

**Configuration**:
```
1. Create rule: When status changed
2. Add condition: Status changed to (list all statuses)
3. Add action: Set field "PICERL Phase"
   - Use branch conditions for each status
   - Map to corresponding phase
4. Add action: Set timestamp field
```

---

### Automation Rule 3: Auto-link Knowledge Base Articles
```
Rule Name: Auto-link Primary Playbook
Trigger: Incident Category set
Condition: Category is not empty
Actions:
  1. Look up playbook for category
  2. Set "Primary Playbook" field
  3. Add comment with playbook link
```

**Configuration**:
```
1. Create rule: When field value changed (Incident Category)
2. Add branch conditions for each category
3. For each branch:
   - Set "Primary Playbook" to appropriate KB-XXXX
   - Add comment: "Playbook: [Link to Confluence]"
```

---

### Automation Rule 4: Prompt for Playbook Effectiveness
```
Rule Name: Request Playbook Effectiveness Rating
Trigger: Issue transitioned to Closed
Condition: Playbook Effectiveness is empty
Actions:
  1. Add comment: "Please rate playbook effectiveness"
  2. Send notification to assignee
  3. (Optional) Block closure until rated
```

**Configuration**:
```
1. Create rule: When status changed to Closed
2. Add condition: IF "Playbook Effectiveness" is empty
3. Add action: Add comment requesting rating
4. Add action: Send email to current user
5. (Optional) Add validator to require field
```

---

### Automation Rule 5: Auto-populate NIST CSF Function
```
Rule Name: Auto-populate CSF Function
Trigger: Status changed
Condition: Status in (workflow states)
Actions:
  1. Map status to CSF function
  2. Set "NIST CSF Function" field
```

**Configuration**:
```
1. Create rule: When status changed
2. Add branch conditions:
   - IF status = Triage: Set CSF Function = Detect (DE)
   - IF status = Containment: Set CSF Function = Respond (RS)
   - IF status = Recovery: Set CSF Function = Recover (RC)
   - etc.
```

---

### Automation Rule 6: Link RE&CT Actions
```
Rule Name: Suggest RE&CT Actions
Trigger: Status changed to specific states
Condition: Status in (Containment, Eradication, Recovery, Post-Incident)
Actions:
  1. Add comment with suggested RE&CT actions
  2. Link to RE&CT documentation
```

**Configuration**:
```
1. Create rule: When status changed
2. Add branch conditions for each relevant status
3. For each branch:
   - Add comment with suggested RA codes
   - Example: "Suggested RE&CT actions: RA3101, RA3201, RA3301"
   - Link to RE&CT playbook
```

---

## Dashboard Setup

### Dashboard 1: Configuration Items Overview

**Widgets**:
1. **Detection Analytics Coverage**
   - Type: Pie chart
   - Data: Incidents by Detection Analytic
   - Purpose: Show which analytics are most active

2. **Framework Compliance**
   - Type: Multi-bar chart
   - Data: Incidents mapped to frameworks (CSF, PICERL, ATT&CK)
   - Purpose: Track framework adoption

3. **Knowledge Base Usage**
   - Type: Table
   - Data: Top KB articles by incident count
   - Purpose: Identify most useful playbooks

4. **MITRE ATT&CK Heatmap**
   - Type: External iframe (ATT&CK Navigator)
   - Data: Technique frequency
   - Purpose: Visualize threat landscape

---

### Dashboard 2: Detection Effectiveness

**Widgets**:
1. **True Positive Rate by Analytic**
   - Type: Bar chart
   - Data: TP rate per ANALYTIC-ID
   - Purpose: Measure detection accuracy

2. **MTTR by Playbook**
   - Type: Table
   - Data: Average MTTR grouped by Primary Playbook
   - Purpose: Measure playbook effectiveness

3. **DeTT&CT Coverage Score**
   - Type: Gauge
   - Data: Overall detection coverage %
   - Purpose: Track detection maturity

4. **Detection Gaps**
   - Type: Table
   - Data: ATT&CK techniques without detection
   - Purpose: Prioritize gap closure

---

### Dashboard 3: Incident Response Maturity

**Widgets**:
1. **PICERL Phase Distribution**
   - Type: Pie chart
   - Data: Incidents by current phase
   - Purpose: Identify bottlenecks

2. **Phase Duration Trends**
   - Type: Line chart
   - Data: Avg duration per phase over time
   - Purpose: Track improvement

3. **Framework Coverage**
   - Type: Scorecard
   - Metrics: % incidents with CSF, PICERL, ATT&CK mappings
   - Purpose: Measure adoption

4. **Playbook Effectiveness**
   - Type: Bar chart
   - Data: Avg effectiveness rating by playbook
   - Purpose: Identify playbooks needing improvement

---

## Implementation Checklist

### Phase 1: Core CI Fields (Week 1)
- [ ] Create Detection Analytics field
- [ ] Create Detection Source field (if not exists)
- [ ] Create Knowledge Base References field
- [ ] Create Primary Playbook field
- [ ] Associate fields with issue types
- [ ] Test field visibility

### Phase 2: Framework Fields (Week 2)
- [ ] Create MITRE ATT&CK Tactics field
- [ ] Create MITRE ATT&CK Techniques field
- [ ] Create NIST CSF Function field
- [ ] Create NIST CSF Categories field
- [ ] Create PICERL Phase field
- [ ] Create RE&CT Actions field

### Phase 3: Automation (Week 3)
- [ ] Configure auto-populate Detection Analytics
- [ ] Configure auto-populate PICERL Phase
- [ ] Configure auto-link Primary Playbook
- [ ] Configure auto-populate CSF Function
- [ ] Configure playbook effectiveness prompt
- [ ] Test all automation rules

### Phase 4: Dashboards (Week 4)
- [ ] Create Configuration Items dashboard
- [ ] Create Detection Effectiveness dashboard
- [ ] Create Incident Response Maturity dashboard
- [ ] Configure ATT&CK Navigator integration
- [ ] Test dashboard performance

### Phase 5: Training & Rollout (Week 5)
- [ ] Train analysts on new fields
- [ ] Create quick reference guide
- [ ] Document field usage
- [ ] Conduct pilot with test incidents
- [ ] Gather feedback and adjust

---

## Maintenance

### Weekly
- Review automation rule execution logs
- Monitor field usage
- Address any configuration issues

### Monthly
- Audit field population completeness
- Review dashboard accuracy
- Update field options as needed

### Quarterly
- Full configuration review
- Update mappings (ATT&CK, CSF, playbooks)
- Optimize automation rules
- Refresh dashboards

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: JIRA Administrators
