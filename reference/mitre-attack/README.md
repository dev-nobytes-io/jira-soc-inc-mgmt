# MITRE ATT&CK Integration for SOC Case Management

## Overview

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. This document describes how ATT&CK is integrated into SOC case management in JIRA for threat intelligence, detection coverage, and incident response.

## ATT&CK Framework Structure

### Tactics (TA codes)
High-level adversary objectives during an attack

### Techniques (T codes)
Methods adversaries use to achieve tactical objectives

### Sub-techniques (T codes with .xxx)
More specific descriptions of techniques

### Procedures
Specific implementations by adversary groups

## ATT&CK Tactics

| Tactic | Code | Description | Common in SOC |
|--------|------|-------------|---------------|
| **Reconnaissance** | TA0043 | Gather information for planning | Low |
| **Resource Development** | TA0042 | Establish resources for operations | Low |
| **Initial Access** | TA0001 | Get into the network | ✓ High |
| **Execution** | TA0002 | Run malicious code | ✓ High |
| **Persistence** | TA0003 | Maintain foothold | ✓ High |
| **Privilege Escalation** | TA0004 | Gain higher permissions | ✓ Medium |
| **Defense Evasion** | TA0005 | Avoid detection | ✓ High |
| **Credential Access** | TA0006 | Steal credentials | ✓ High |
| **Discovery** | TA0007 | Explore environment | ✓ Medium |
| **Lateral Movement** | TA0008 | Move through network | ✓ High |
| **Collection** | TA0009 | Gather data of interest | ✓ Medium |
| **Command and Control** | TA0011 | Communicate with compromised systems | ✓ High |
| **Exfiltration** | TA0010 | Steal data | ✓ High |
| **Impact** | TA0040 | Disrupt availability or integrity | ✓ Medium |

## Common Techniques by Incident Type

### Phishing (UC-010)
- **T1566**: Phishing
  - T1566.001: Spearphishing Attachment
  - T1566.002: Spearphishing Link
  - T1566.003: Spearphishing via Service
- **T1204**: User Execution
  - T1204.001: Malicious Link
  - T1204.002: Malicious File

### Malware Execution (UC-002)
- **T1059**: Command and Scripting Interpreter
  - T1059.001: PowerShell
  - T1059.003: Windows Command Shell
  - T1059.005: Visual Basic
  - T1059.007: JavaScript
- **T1204**: User Execution
- **T1053**: Scheduled Task/Job
  - T1053.005: Scheduled Task

### Credential Theft (UC-004)
- **T1003**: OS Credential Dumping
  - T1003.001: LSASS Memory
  - T1003.002: Security Account Manager
  - T1003.003: NTDS
- **T1110**: Brute Force
  - T1110.001: Password Guessing
  - T1110.002: Password Cracking
  - T1110.003: Password Spraying
- **T1558**: Steal or Forge Kerberos Tickets
  - T1558.003: Kerberoasting
  - T1558.004: AS-REP Roasting

### Lateral Movement (UC-005)
- **T1021**: Remote Services
  - T1021.001: Remote Desktop Protocol
  - T1021.002: SMB/Windows Admin Shares
  - T1021.003: Distributed Component Object Model
  - T1021.006: Windows Remote Management
- **T1047**: Windows Management Instrumentation
- **T1550**: Use Alternate Authentication Material
  - T1550.002: Pass the Hash
  - T1550.003: Pass the Ticket

### Data Exfiltration (UC-006)
- **T1567**: Exfiltration Over Web Service
  - T1567.002: Exfiltration to Cloud Storage
- **T1041**: Exfiltration Over C2 Channel
- **T1048**: Exfiltration Over Alternative Protocol
- **T1537**: Transfer Data to Cloud Account

### Persistence (UC-009)
- **T1547**: Boot or Logon Autostart Execution
  - T1547.001: Registry Run Keys / Startup Folder
  - T1547.009: Shortcut Modification
- **T1053**: Scheduled Task/Job
  - T1053.005: Scheduled Task
- **T1136**: Create Account
  - T1136.001: Local Account
  - T1136.002: Domain Account
- **T1098**: Account Manipulation
  - T1098.001: Additional Cloud Credentials

### Ransomware (UC-007)
- **T1486**: Data Encrypted for Impact
- **T1490**: Inhibit System Recovery
- **T1489**: Service Stop
- **T1491**: Defacement

## JIRA Integration

### Custom Fields for ATT&CK

#### 1. MITRE ATT&CK Tactics
- **Type**: Multi-select dropdown
- **Values**: All 14 tactics (see table above)
- **Usage**: High-level categorization of adversary behavior
- **Required**: Recommended for all incidents

**Configuration**:
```
Field: MITRE ATT&CK Tactics
Type: Checkboxes (multi-select)
Options:
  - Initial Access (TA0001)
  - Execution (TA0002)
  - Persistence (TA0003)
  - Privilege Escalation (TA0004)
  - Defense Evasion (TA0005)
  - Credential Access (TA0006)
  - Discovery (TA0007)
  - Lateral Movement (TA0008)
  - Collection (TA0009)
  - Exfiltration (TA0010)
  - Command and Control (TA0011)
  - Impact (TA0040)
  - Reconnaissance (TA0043)
  - Resource Development (TA0042)
```

#### 2. MITRE ATT&CK Techniques
- **Type**: Multi-line text or Labels
- **Format**: `T{ID}` or `T{ID}.{Sub-ID}`
- **Example**: `T1003.001`, `T1566.002`
- **Usage**: Specific technique tracking

**Configuration**:
```
Field: MITRE ATT&CK Techniques
Type: Labels or Multi-line text
Format: T-codes (e.g., "T1003.001", "T1566.002")
Searchable: Yes
```

#### 3. ATT&CK Technique Details
- **Type**: Multi-line text
- **Usage**: Detailed description of techniques observed
- **Format**: Free text with technique names and descriptions

#### 4. ATT&CK Procedure
- **Type**: Multi-line text
- **Usage**: Specific procedure details and adversary implementation
- **Format**: Narrative description

### Automation Rules for ATT&CK

#### Auto-populate Tactics from Techniques
```
Trigger: MITRE ATT&CK Techniques field updated
Condition: Techniques field contains T-code
Action:
  Parse T-codes from Techniques field
  Look up associated Tactics
  Auto-populate Tactics field

Example:
  IF Techniques contains "T1003.001":
    Add "Credential Access" to Tactics
  IF Techniques contains "T1566.001":
    Add "Initial Access" to Tactics
```

#### Auto-populate from Incident Category
```
Trigger: Incident Category is set
Condition: Category is not empty
Action: Add common techniques for category

Mappings:
  Phishing → T1566.001, T1566.002, T1204.001
  Malware → T1059.001, T1204.002, T1053.005
  Credential Theft → T1003.001, T1110.003, T1558.003
  Lateral Movement → T1021.001, T1021.002, T1047
  Data Exfiltration → T1567.002, T1041
  Ransomware → T1486, T1490, T1489
```

#### Link to Detection Analytics
```
Trigger: ATT&CK Technique added
Condition: Technique has detection analytic
Action:
  Look up ANALYTIC-{ID} for technique
  Populate Detection Analytics field
  Add comment: "Detection: [ANALYTIC-ID] covers [Technique]"
```

#### Link to Response Playbook
```
Trigger: ATT&CK Tactic added
Condition: Tactic has response playbook
Action:
  Look up playbook for tactic
  Add KB link to Knowledge Base References field
  Add comment with playbook link
```

## ATT&CK Navigator Integration

### Export JIRA Data to Navigator
Generate ATT&CK Navigator layer from JIRA incident data

**Process**:
1. Query JIRA for incidents with ATT&CK techniques
2. Count incidents per technique
3. Generate Navigator JSON layer
4. Import into ATT&CK Navigator
5. Visualize detection coverage

**Navigator Layer Use Cases**:
- Incident heatmap (techniques by frequency)
- Detection coverage (techniques with analytics)
- Response coverage (techniques with playbooks)
- Trend analysis (techniques over time)

### Navigator Layer Example
```json
{
  "name": "SOC Incident Coverage - Q4 2025",
  "versions": {
    "navigator": "4.5",
    "layer": "4.3"
  },
  "domain": "enterprise-attack",
  "description": "ATT&CK techniques observed in incidents Q4 2025",
  "techniques": [
    {
      "techniqueID": "T1003.001",
      "score": 23,
      "comment": "23 incidents, ANALYTIC-004 deployed",
      "color": "#ff6666"
    },
    {
      "techniqueID": "T1566.001",
      "score": 47,
      "comment": "47 incidents, ANALYTIC-010 deployed",
      "color": "#ff3333"
    }
  ]
}
```

## ATT&CK Coverage Tracking

### Detection Coverage Matrix

| Tactic | Total Techniques | Detected | Coverage % | Gap Count |
|--------|------------------|----------|------------|-----------|
| Initial Access | 9 | 7 | 78% | 2 |
| Execution | 12 | 10 | 83% | 2 |
| Persistence | 19 | 12 | 63% | 7 |
| Privilege Escalation | 13 | 8 | 62% | 5 |
| Defense Evasion | 42 | 18 | 43% | 24 |
| Credential Access | 15 | 11 | 73% | 4 |
| Discovery | 29 | 14 | 48% | 15 |
| Lateral Movement | 9 | 7 | 78% | 2 |
| Collection | 17 | 9 | 53% | 8 |
| Command and Control | 16 | 10 | 63% | 6 |
| Exfiltration | 9 | 6 | 67% | 3 |
| Impact | 13 | 8 | 62% | 5 |

### Coverage Calculation
```
Coverage % = (Techniques with Detection / Total Techniques) * 100

Technique has detection if:
  - ANALYTIC-{ID} exists for technique
  - Detection validated and in production
  - Alert routing to JIRA configured
```

### Gap Analysis Process
1. **Identify Gaps**: Techniques without detection
2. **Risk Assessment**: Evaluate likelihood and impact
3. **Prioritization**: Rank gaps by risk
4. **Detection Development**: Create analytics for high-priority gaps
5. **Validation**: Test and deploy new detections
6. **Coverage Update**: Recalculate coverage metrics

## ATT&CK Reporting

### Report 1: Top 10 Techniques Observed
```
Query: Count incidents by ATT&CK technique
Sort: Descending by count
Output: Table with technique ID, name, count

Example Output:
| Technique | Name | Incident Count |
|-----------|------|----------------|
| T1566.001 | Spearphishing Attachment | 47 |
| T1003.001 | LSASS Memory | 23 |
| T1059.001 | PowerShell | 19 |
| T1110.003 | Password Spraying | 15 |
| T1021.001 | Remote Desktop Protocol | 12 |
```

### Report 2: Tactic Distribution
```
Widget: Pie chart
Data: Incident count by tactic
Purpose: Identify most common attack phases
```

### Report 3: Detection Coverage Heatmap
```
Widget: ATT&CK Navigator layer
Data: Techniques colored by detection status
Colors:
  - Green: Detection deployed
  - Yellow: Detection in development
  - Red: No detection (gap)
Purpose: Visualize detection coverage
```

### Report 4: Technique Trend Analysis
```
Widget: Line chart
Data: Technique usage over time (monthly)
Purpose: Identify trending TTPs
```

## ATT&CK Enrichment

### Automated Enrichment Process
```
When: Incident created in JIRA
Then:
  1. Parse IOCs and observables
  2. Query threat intelligence for IOCs
  3. Extract associated ATT&CK techniques
  4. Auto-populate Techniques field
  5. Add comment with TI source
```

### Threat Intelligence Integration
```
Sources:
  - MISP (Malware Information Sharing Platform)
  - AlienVault OTX
  - Threat intelligence feeds
  - Vendor reports

Process:
  1. IOC lookup in TI platform
  2. Extract ATT&CK tags
  3. Enrich JIRA incident
  4. Link to TI report
```

## Mapping Templates

### Incident Category → ATT&CK Techniques

#### Phishing
```
Primary Techniques:
  - T1566.001 (Spearphishing Attachment)
  - T1566.002 (Spearphishing Link)
  - T1204.001 (Malicious Link)
  - T1204.002 (Malicious File)

Secondary Techniques (if compromised):
  - T1059.001 (PowerShell)
  - T1003.001 (LSASS Memory)
  - T1071.001 (Web Protocols - C2)
```

#### Malware
```
Primary Techniques:
  - T1059 (Command and Scripting Interpreter)
  - T1204 (User Execution)
  - T1053.005 (Scheduled Task)
  - T1547.001 (Registry Run Keys)

Secondary Techniques:
  - T1071 (Application Layer Protocol)
  - T1095 (Non-Application Layer Protocol)
  - T1486 (Data Encrypted for Impact - if ransomware)
```

#### Credential Theft
```
Primary Techniques:
  - T1003.001 (LSASS Memory)
  - T1003.002 (Security Account Manager)
  - T1558.003 (Kerberoasting)
  - T1110 (Brute Force)

Secondary Techniques:
  - T1552.001 (Credentials In Files)
  - T1555 (Credentials from Password Stores)
```

### Detection Analytics → ATT&CK Techniques

| Analytic ID | Technique | Sub-technique | Tactic |
|-------------|-----------|---------------|--------|
| ANALYTIC-001 | T1059.001 | PowerShell | Execution |
| ANALYTIC-002 | T1110.003 | Password Spraying | Credential Access |
| ANALYTIC-003 | T1003.001 | LSASS Memory | Credential Access |
| ANALYTIC-004 | T1047 | WMI | Execution, Lateral Movement |
| ANALYTIC-005 | T1567.002 | Cloud Storage | Exfiltration |
| ANALYTIC-006 | T1204 | User Execution | Execution |
| ANALYTIC-007 | T1053.005 | Scheduled Task | Persistence, Privilege Escalation |
| ANALYTIC-008 | T1547.001 | Registry Run Keys | Persistence, Privilege Escalation |
| ANALYTIC-009 | T1558.003 | Kerberoasting | Credential Access |
| ANALYTIC-010 | T1566 | Phishing | Initial Access |

## Implementation Guide

### Phase 1: Field Configuration
1. Create ATT&CK custom fields
2. Configure dropdown values (tactics)
3. Set up labels/text fields (techniques)
4. Associate with issue types

### Phase 2: Populate Mappings
1. Map incident categories to techniques
2. Map detection analytics to techniques
3. Create automation lookup tables
4. Document mappings

### Phase 3: Automation Setup
1. Auto-populate tactics from techniques
2. Auto-populate techniques from category
3. Link detection analytics
4. Link response playbooks

### Phase 4: Coverage Tracking
1. Calculate baseline coverage
2. Identify gaps
3. Prioritize gap closure
4. Track improvement over time

### Phase 5: Reporting
1. Deploy ATT&CK dashboards
2. Generate Navigator layers
3. Create coverage reports
4. Track trending techniques

## ATT&CK Resources

### Official Resources
- ATT&CK Website: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- ATT&CK for Enterprise: https://attack.mitre.org/matrices/enterprise/
- Technique Matrix: https://attack.mitre.org/techniques/enterprise/

### Tools
- ATT&CK Navigator (visualization)
- CALDERA (adversary emulation)
- Atomic Red Team (testing)
- DeTT&CT (detection coverage)
- ATT&CK Sync (JIRA integration)

### Community Resources
- ATT&CK Evaluations
- CTI Blueprints
- MITRE Engenuity
- Community contributions

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Framework**: MITRE ATT&CK for Enterprise v14
**Maintained By**: Threat Intelligence Team
