# NIST Cybersecurity Framework (CSF) 2.0 Integration

## Overview

The NIST Cybersecurity Framework 2.0 provides a structured approach to managing cybersecurity risks. This document maps CSF 2.0 functions, categories, and subcategories to SOC incident management workflows in JIRA.

## CSF 2.0 Functions

The framework consists of 6 core functions:

1. **GOVERN (GV)** - Establish and monitor cybersecurity risk management strategy
2. **IDENTIFY (ID)** - Understand assets, risks, and vulnerabilities
3. **PROTECT (PR)** - Implement safeguards to ensure critical services
4. **DETECT (DE)** - Identify cybersecurity events in a timely manner
5. **RESPOND (RS)** - Take action regarding detected cybersecurity incidents
6. **RECOVER (RC)** - Restore capabilities and services impaired by incidents

## CSF to SOC Workflow Mapping

### GOVERN (GV) Function

#### GV.OC - Organizational Context
**JIRA Mapping**: Project governance, team structure, escalation paths

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.OC-01 | Mission objectives inform cybersecurity strategy | Severity classification aligned with business impact |
| GV.OC-02 | Internal and external stakeholders understood | Stakeholder field, Communication Status field |
| GV.OC-03 | Legal, regulatory, contractual requirements understood | Compliance tags, Regulatory Notification field |
| GV.OC-04 | Critical objectives, functions, and services understood | Asset criticality tiers, Affected Assets field |
| GV.OC-05 | Outcomes and performance metrics defined | Dashboards for MTTR, MTTD, SLA compliance |

#### GV.RM - Risk Management Strategy
**JIRA Mapping**: Risk assessment, incident severity, threat intelligence

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.RM-01 | Risk management objectives established | Incident severity levels, SLA definitions |
| GV.RM-02 | Risk appetite and risk tolerance established | Severity classification, escalation thresholds |
| GV.RM-03 | Risk management strategy established | Playbooks, response procedures, RE&CT actions |
| GV.RM-04 | Strategic direction considers risks | Executive reporting, Post-Incident Reviews |
| GV.RM-05 | Cybersecurity is part of enterprise risk management | Integration with GRC tools, Risk register |

#### GV.RR - Roles, Responsibilities, and Authorities
**JIRA Mapping**: Assignment, teams, permissions

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.RR-01 | Cybersecurity roles and responsibilities established | Assigned Team field, RACI matrix |
| GV.RR-02 | Roles and responsibilities understood and communicated | Permission scheme, Assignable users |
| GV.RR-03 | Adequate resources allocated | Team capacity tracking, Workload dashboards |
| GV.RR-04 | Cybersecurity integrated into enterprise risk management | Risk assessment field, Executive visibility |

#### GV.PO - Policy
**JIRA Mapping**: Policy violations, compliance tracking

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.PO-01 | Policy established and communicated | Policy Violation issue type, Policy reference field |
| GV.PO-02 | Policy enforced | Automated policy checks, Compliance monitoring |

#### GV.OV - Oversight
**JIRA Mapping**: Management reporting, audits, reviews

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.OV-01 | Cybersecurity oversight maintained | SOC dashboard for management, Executive reports |
| GV.OV-02 | Cybersecurity program monitored | Metrics tracking, KPI dashboards |
| GV.OV-03 | Cybersecurity results reported to leadership | Monthly reports, Incident trend analysis |

#### GV.SC - Cybersecurity Supply Chain Risk Management
**JIRA Mapping**: Third-party incidents, vendor risk

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| GV.SC-01 | Cybersecurity supply chain risks identified | Third-party incident category |
| GV.SC-02 | Suppliers and third-party partners assessed | Vendor risk field |

### IDENTIFY (ID) Function

#### ID.AM - Asset Management
**JIRA Mapping**: Affected Assets field, Asset inventory

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| ID.AM-01 | Physical devices and systems inventoried | Affected Assets field (hosts, servers) |
| ID.AM-02 | Software platforms and applications inventoried | Affected Assets field (applications) |
| ID.AM-03 | Organizational communication and data flows mapped | Network diagram references, Data flow field |
| ID.AM-04 | External information systems catalogued | Third-party systems field |
| ID.AM-05 | Resources prioritized based on criticality | Asset criticality tier field |
| ID.AM-07 | Roles and responsibilities for inventory maintained | Asset owner field |
| ID.AM-08 | Systems, hardware, software, services tracked | CMDB integration, CI linking |

#### ID.RA - Risk Assessment
**JIRA Mapping**: Incident severity, risk assessment

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| ID.RA-01 | Asset vulnerabilities identified and documented | Vulnerability issue type, CVE field |
| ID.RA-02 | Cyber threat intelligence received | Threat Intelligence tags, IOC field |
| ID.RA-03 | Internal and external threats identified | Threat actor field, Attack vector field |
| ID.RA-04 | Potential impacts and likelihoods identified | Impact assessment field, Risk score |
| ID.RA-05 | Threats, vulnerabilities, likelihoods, and impacts used to determine risk | Incident severity calculation |
| ID.RA-06 | Risk responses identified and prioritized | Response priority, Mitigation actions |
| ID.RA-07 | Risk responses monitored | Risk tracking, Follow-up tasks |
| ID.RA-08 | Effectiveness of risk responses assessed | Post-incident review, Lessons learned |

#### ID.IM - Improvement
**JIRA Mapping**: Lessons learned, continuous improvement

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| ID.IM-01 | Improvements identified from detection and response | Post-Incident Review issue type |
| ID.IM-02 | Response and recovery plans incorporate lessons learned | Playbook updates, Detection improvements |

### PROTECT (PR) Function

#### PR.AA - Identity Management, Authentication, and Access Control
**JIRA Mapping**: Compromised accounts, credential reset

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| PR.AA-01 | Identities and credentials issued, managed, verified | Compromised Account field, User identity |
| PR.AA-02 | Identities authenticated commensurate with risk | MFA enforcement tracking |
| PR.AA-03 | Identities and credentials revoked when access no longer required | Account disable tracking, Offboarding incidents |
| PR.AA-04 | Identity assertions verified | Session validation, Token verification |
| PR.AA-05 | Access permissions and authorizations defined | Privilege escalation incidents |
| PR.AA-06 | Physical and logical access restricted | Access control violations |

#### PR.DS - Data Security
**JIRA Mapping**: Data exfiltration, data loss incidents

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| PR.DS-01 | Data at rest protected | Encryption violations, Data exposure incidents |
| PR.DS-02 | Data in transit protected | Network security incidents, Unencrypted traffic |
| PR.DS-05 | Protection against data leaks implemented | DLP incidents, Exfiltration detection |
| PR.DS-08 | Integrity checking mechanisms verify data | Integrity violation incidents |
| PR.DS-11 | Backups managed | Backup failure incidents, Ransomware recovery |

#### PR.PS - Platform Security
**JIRA Mapping**: Malware incidents, system compromises

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| PR.PS-01 | Configuration management practices established | Configuration drift incidents |
| PR.PS-02 | Configurations reviewed and updated | Misconfiguration incidents |
| PR.PS-06 | Secure software development practices integrated | Code vulnerability incidents |

### DETECT (DE) Function

#### DE.AE - Anomalies and Events
**JIRA Mapping**: Alert creation, anomaly detection

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| DE.AE-02 | Potentially adverse events analyzed | Alert issue type, Investigation status |
| DE.AE-03 | Event data aggregated and correlated | SIEM integration, Correlation rules |
| DE.AE-04 | Impact of events determined | Impact assessment field, Severity |
| DE.AE-06 | Information on adverse events shared | Threat intelligence sharing, IOC distribution |
| DE.AE-07 | Cyber threat intelligence and other contextual information integrated | Threat intel feeds, Enrichment automation |
| DE.AE-08 | Incidents declared when adverse events meet criteria | Alert → Incident escalation workflow |

#### DE.CM - Continuous Monitoring
**JIRA Mapping**: Detection sources, monitoring coverage

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| DE.CM-01 | Networks and network services monitored | Network incidents, IDS/IPS alerts |
| DE.CM-02 | Physical environment monitored | Physical security incidents |
| DE.CM-03 | Personnel activity and technology usage monitored | Insider threat incidents, UBA alerts |
| DE.CM-04 | Malicious code detected | Malware incidents, AV alerts |
| DE.CM-06 | External service provider activities monitored | Third-party incidents, Vendor alerts |
| DE.CM-07 | Monitoring for unauthorized activity | Anomaly detection, UEBA alerts |
| DE.CM-09 | Computing hardware and software monitored | EDR alerts, System monitoring |

#### DE.DP - Detection Processes
**JIRA Mapping**: Detection analytics, detection coverage

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| DE.DP-01 | Roles and responsibilities for detection defined | Detection team, On-call rotation |
| DE.DP-02 | Detection activities comply with requirements | Detection coverage dashboards, DeTT&CT |
| DE.DP-03 | Detection processes tested | Detection testing incidents, Purple team exercises |
| DE.DP-04 | Event detection information communicated | Alert notifications, Escalation procedures |
| DE.DP-05 | Detection processes continuously improved | Detection tuning, False positive reduction |

### RESPOND (RS) Function

#### RS.MA - Incident Management
**JIRA Mapping**: Incident workflow, case management

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RS.MA-01 | Incident lifecycle managed | Incident issue type, Workflow states |
| RS.MA-02 | Incidents categorized | Incident Category field, MITRE ATT&CK mapping |
| RS.MA-03 | Incidents prioritized | Incident Severity field, Priority |
| RS.MA-04 | Incidents reported | Incident reporting, Stakeholder notifications |
| RS.MA-05 | Incident criteria established | Escalation criteria, Severity definitions |

#### RS.AN - Incident Analysis
**JIRA Mapping**: Investigation status, forensics

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RS.AN-03 | Analysis performed to establish timeline | Timeline field, Evidence collection |
| RS.AN-06 | Actions performed on systems are recorded | Response Actions field, Audit log |
| RS.AN-07 | Incident data and metadata collected and maintained | Evidence Links field, Forensic artifacts |
| RS.AN-08 | Incident analysis information shared | Post-incident review, Lessons learned |

#### RS.RP - Response Planning
**JIRA Mapping**: Playbooks, response procedures

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RS.RP-01 | Response plan executed during and after incident | Playbook execution, RE&CT actions |

#### RS.CO - Communications
**JIRA Mapping**: Communication status, stakeholder notifications

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RS.CO-02 | Events reported consistent with criteria | Reporting criteria, Notification rules |
| RS.CO-03 | Information shared with stakeholders | Communication Status field, Stakeholder updates |
| RS.CO-04 | Coordination with stakeholders occurs | Collaboration notes, Meeting records |
| RS.CO-05 | Voluntary information sharing occurs | Threat intel sharing, ISAC participation |

#### RS.MI - Incident Mitigation
**JIRA Mapping**: Containment, eradication workflows

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RS.MI-01 | Incidents contained | Containment workflow state, Containment actions |
| RS.MI-02 | Incidents eradicated | Eradication workflow state, Removal actions |

### RECOVER (RC) Function

#### RC.RP - Recovery Planning
**JIRA Mapping**: Recovery workflow, restoration procedures

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RC.RP-01 | Recovery plan executed during and after incident | Recovery workflow state, Restoration tasks |

#### RC.IM - Improvements
**JIRA Mapping**: Lessons learned, post-incident review

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RC.IM-01 | Recovery plans incorporate lessons learned | Post-Incident Review, Improvement tasks |
| RC.IM-02 | Recovery strategies updated | Playbook updates, Process improvements |

#### RC.CO - Communications
**JIRA Mapping**: Recovery communications

| Subcategory | Description | JIRA Implementation |
|-------------|-------------|---------------------|
| RC.CO-01 | Public relations managed | Public communication tracking |
| RC.CO-02 | Reputation after incident repaired | Reputation management tasks |
| RC.CO-03 | Recovery activities communicated | Recovery status updates |

## Incident Workflow to CSF Mapping

### Workflow State → CSF Function Mapping

| JIRA Workflow State | Primary CSF Function | CSF Categories |
|---------------------|----------------------|----------------|
| **New** | IDENTIFY (ID) | ID.RA (Risk Assessment) |
| **Triage** | DETECT (DE) | DE.AE (Anomalies and Events), DE.DP (Detection Processes) |
| **Investigation** | DETECT (DE) / RESPOND (RS) | DE.AE, RS.AN (Incident Analysis) |
| **Containment** | RESPOND (RS) | RS.MI-01 (Incidents contained) |
| **Eradication** | RESPOND (RS) | RS.MI-02 (Incidents eradicated) |
| **Recovery** | RECOVER (RC) | RC.RP (Recovery Planning) |
| **Post-Incident** | RECOVER (RC) | RC.IM (Improvements) |
| **Closed** | GOVERN (GV) | GV.OV (Oversight), GV.RM (Risk Management) |

### Activity Type → CSF Mapping

| Activity | CSF Function | Subcategory |
|----------|--------------|-------------|
| Threat intelligence analysis | DETECT (DE) | DE.AE-07 |
| Alert triage | DETECT (DE) | DE.AE-02, DE.AE-08 |
| Evidence collection | RESPOND (RS) | RS.AN-07 |
| Timeline analysis | RESPOND (RS) | RS.AN-03 |
| Disable compromised account | RESPOND (RS) | RS.MI-01 |
| Remove malware | RESPOND (RS) | RS.MI-02 |
| System restoration | RECOVER (RC) | RC.RP-01 |
| Lessons learned documentation | RECOVER (RC) | RC.IM-01 |
| Detection improvement | DETECT (DE) | DE.DP-05 |
| Policy update | GOVERN (GV) | GV.PO-01 |

## JIRA Custom Fields for CSF 2.0

### Required Custom Fields

#### 1. NIST CSF Function
- **Type**: Single-select dropdown
- **Options**: Govern, Identify, Protect, Detect, Respond, Recover
- **Default**: Auto-populated based on workflow state
- **Usage**: Primary CSF function for incident activity

#### 2. NIST CSF Categories
- **Type**: Multi-select or Labels
- **Format**: `{Function}.{Category}` (e.g., "DE.AE", "RS.MI")
- **Usage**: Specific CSF categories addressed

#### 3. NIST CSF Subcategories
- **Type**: Multi-line text or Labels
- **Format**: `{Function}.{Category}-{ID}` (e.g., "DE.AE-07", "RS.MI-01")
- **Usage**: Detailed CSF subcategory tracking

### Automation Rules for CSF

#### Auto-populate CSF Function
```
Trigger: Workflow status changed
Condition: Status in (Triage, Investigation, Containment, etc.)
Action: Set "NIST CSF Function" based on mapping table
```

#### Auto-populate CSF Categories
```
Trigger: Incident Category set
Condition: Category is not empty
Action: Add relevant CSF categories based on incident type
Example:
  - Malware → DE.CM-04, RS.MI-02
  - Phishing → DE.CM-03, RS.MI-01
  - Data Exfiltration → PR.DS-05, RS.AN-07
```

## CSF Compliance Reporting

### Dashboard: CSF Coverage by Function

**Widgets**:
1. Pie chart: Incidents by CSF Function
2. Bar chart: Incidents by CSF Category
3. Table: Top 10 CSF Subcategories
4. Trend: CSF function coverage over time

### Report: CSF Gap Analysis

**Query**: Identify CSF subcategories with low incident coverage

```
FOR EACH CSF Subcategory:
  Count incidents mapped to subcategory
  IF count = 0:
    FLAG as "No Coverage"
  IF count < threshold:
    FLAG as "Low Coverage"
```

### Report: Incident Handling Maturity

**Metrics**:
- % incidents with CSF mapping
- Avg CSF categories per incident
- CSF function distribution
- Trend: Maturity over time

## Implementation Guide

### Phase 1: Field Configuration
1. Create CSF custom fields in JIRA
2. Configure dropdown values
3. Set default values
4. Associate with issue types

### Phase 2: Automation Setup
1. Create workflow transition rules
2. Configure auto-population logic
3. Test with sample incidents
4. Deploy to production

### Phase 3: Training & Adoption
1. Train analysts on CSF concepts
2. Demonstrate field usage
3. Create quick reference guide
4. Monitor adoption metrics

### Phase 4: Reporting & Optimization
1. Deploy CSF dashboards
2. Generate baseline reports
3. Identify gaps
4. Optimize mappings

## References

- NIST CSF 2.0: https://www.nist.gov/cyberframework
- CSF Implementation Guide
- CSF to MITRE ATT&CK Mapping
- CSF Reference Tool

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Framework**: NIST Cybersecurity Framework 2.0
**Maintained By**: SOC Engineering Team
