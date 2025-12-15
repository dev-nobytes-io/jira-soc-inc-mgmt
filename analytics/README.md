# Detection Analytics Repository

## Overview

This repository contains production-ready detection analytics for Splunk SIEM, including SPL queries, notable event configurations, and SOAR playbook integrations.

## Repository Structure

```
analytics/
├── active-directory/          # AD-specific detections
│   ├── privilege-escalation.md
│   ├── kerberos-attacks.md
│   ├── account-manipulation.md
│   └── group-enumeration.md
├── admin-abuse/               # Admin abuse detections
│   ├── unauthorized-admin-actions.md
│   ├── self-administration.md
│   ├── policy-violations.md
│   └── suspicious-admin-activity.md
├── network/                   # Network-based detections (Corelight)
│   ├── lateral-movement.md
│   ├── port-scanning.md
│   ├── unusual-protocols.md
│   └── data-exfiltration.md
├── enumeration/               # Enumeration activity detections
│   ├── ad-enumeration.md
│   ├── network-reconnaissance.md
│   └── service-discovery.md
├── lateral-movement/          # Lateral movement detections
│   ├── remote-execution.md
│   ├── credential-dumping.md
│   └── pass-the-hash.md
├── persistence/               # Persistence mechanism detections
│   ├── scheduled-tasks.md
│   ├── registry-persistence.md
│   └── account-creation.md
├── notable-events/            # Splunk notable event configurations
│   └── notable-configurations.md
└── soar-playbooks/           # Splunk SOAR playbooks
    └── soar-playbooks.md
```

## Detection Categories

### Active Directory Detections
- Unauthorized privilege escalation
- Kerberoasting attacks
- Golden/Silver ticket attacks
- Account manipulation
- Group policy modifications
- LDAP enumeration
- DCSync attacks

### Admin Abuse Detections
- Self-service admin rights grants
- Unauthorized admin tool usage
- Off-hours admin activity
- Admin account sharing
- Policy violations
- Suspicious privilege usage

### Network Detections (Corelight)
- Internal port scanning
- Lateral movement via SMB/RDP
- Unusual protocol usage
- C2 beacon detection
- Data exfiltration patterns
- DNS tunneling

### Enumeration Detections
- AD reconnaissance
- Network mapping
- Service discovery
- Credential access attempts

## Detection Format

Each detection includes:

```markdown
# Detection Name

## Overview
- **Detection ID**: DET-XXX
- **MITRE ATT&CK**: [Technique IDs]
- **Severity**: Critical/High/Medium/Low
- **Data Sources**: [Required data sources]

## Description
[What this detection identifies]

## SPL Query
[Production-ready Splunk query]

## Notable Event Configuration
- Title
- Description
- Severity
- Recommended Actions

## False Positives
[Common false positive scenarios]

## Tuning Guidance
[How to reduce false positives]

## Response Actions
[Recommended response procedures]

## SOAR Integration
[Automation opportunities]
```

## Quick Start

### 1. Deploy Detection

```spl
# Copy SPL query from detection file
# Save as Alert in Splunk
# Configure schedule (typically 5-15 min intervals)
# Set notable event action
```

### 2. Configure Notable Event

```
Title: [Detection Name] - $user$ on $dest$
Description: [From detection file]
Severity: [From detection file]
Assigned: SOC Team
```

### 3. Create JIRA Integration

All notable events auto-create JIRA alerts via webhook (see integrations/README.md)

## Detection Statistics

| Category | Count | Critical | High | Medium | Low |
|----------|-------|----------|------|--------|-----|
| Active Directory | 12 | 4 | 5 | 2 | 1 |
| Admin Abuse | 10 | 3 | 4 | 3 | 0 |
| Network | 8 | 2 | 4 | 2 | 0 |
| Enumeration | 6 | 0 | 3 | 3 | 0 |
| Lateral Movement | 7 | 3 | 3 | 1 | 0 |
| Persistence | 6 | 2 | 3 | 1 | 0 |
| **Total** | **49** | **14** | **22** | **12** | **1** |

## Data Source Requirements

### Required Splunk Add-ons
- Splunk Add-on for Microsoft Windows
- Splunk Add-on for Active Directory
- Splunk Add-on for Microsoft Sysmon
- Splunk Stream or Corelight TA
- Splunk Add-on for Microsoft Cloud Services (optional - O365/Azure)

### Required Data Sources
- Windows Security Event Logs (4624, 4625, 4672, 4768, 4769, 4776, etc.)
- Windows System Event Logs
- Sysmon Logs (Process creation, Network connections, etc.)
- Active Directory logs
- Network traffic (Corelight/Zeek, NetFlow, etc.)
- DNS logs
- Proxy/Firewall logs

### Data Models Used
- Authentication
- Change
- Network_Traffic
- Endpoint

## Deployment Checklist

### Phase 1: Critical Detections (Week 1)
- [ ] Privilege Escalation Detection
- [ ] Kerberoasting Detection
- [ ] Admin Account Abuse
- [ ] Lateral Movement (SMB/RDP)
- [ ] Suspicious PowerShell Execution

### Phase 2: High Priority (Week 2)
- [ ] AD Enumeration
- [ ] Self-Administration Detection
- [ ] Port Scanning
- [ ] Pass-the-Hash Detection
- [ ] Golden Ticket Detection

### Phase 3: Medium Priority (Week 3-4)
- [ ] Policy Violation Detections
- [ ] Network Reconnaissance
- [ ] Persistence Mechanisms
- [ ] Unusual Protocol Usage
- [ ] Service Discovery

### Phase 4: Optimization (Ongoing)
- [ ] Tune all detections
- [ ] Reduce false positives
- [ ] Enhance coverage
- [ ] Update based on threat intel

## Tuning & Maintenance

### Weekly
- Review notable events generated
- Identify false positive patterns
- Update exclusion lists
- Verify data quality

### Monthly
- Analyze detection effectiveness
- Review true positive rate
- Update detection logic
- Add new detections based on threats

### Quarterly
- Full detection review
- Validate against MITRE ATT&CK
- Update documentation
- Train team on new detections

## MITRE ATT&CK Coverage

### Tactics Covered
- TA0001: Initial Access
- TA0002: Execution
- TA0003: Persistence
- TA0004: Privilege Escalation
- TA0005: Defense Evasion
- TA0006: Credential Access
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0009: Collection
- TA0010: Exfiltration
- TA0011: Command and Control

### Coverage Map

See `/reference/mitre-coverage-map.md` for detailed technique coverage

## Performance Considerations

### Search Optimization
- Use indexed fields when possible
- Avoid wildcards at beginning of searches
- Use `tstats` for data model searches
- Limit time ranges appropriately
- Use summary indexing for expensive searches

### Example Optimized Search
```spl
# Good - Uses tstats and indexed fields
| tstats count from datamodel=Authentication where Authentication.action=success by Authentication.user, Authentication.src

# Avoid - Slow wildcard search
index=* sourcetype=* user=*
```

### Resource Management
- Schedule detections at different times
- Prioritize critical detections
- Use acceleration where appropriate
- Monitor search load

## Integration with JIRA

All detections automatically create JIRA alerts when triggered:

**Webhook Configuration**:
```
Alert Action: Webhook
URL: https://your-jira.atlassian.net/rest/api/3/issue
Headers: Authorization: Bearer $token$

Payload includes:
- Detection Name
- Severity
- Affected User/Host
- IOCs
- MITRE ATT&CK Technique
```

See `/integrations/README.md` for detailed integration setup

## Testing Detections

### Test Environments
- Use isolated test environment
- Generate test data safely
- Validate detection logic
- Measure false positive rate

### Test Data Generation
```powershell
# Example: Generate test event for admin abuse detection
# (In controlled test environment only!)
Add-ADGroupMember -Identity "Domain Admins" -Members "testuser"
```

### Validation Checklist
- [ ] Detection fires on test data
- [ ] Notable event created correctly
- [ ] JIRA ticket auto-created
- [ ] Severity appropriate
- [ ] Context data populated
- [ ] False positive rate acceptable

## Threat Hunting

Use these detections as starting points for threat hunting:

1. **Baseline Normal**: Run detection over 30 days, identify patterns
2. **Hunt for Outliers**: Look for deviations from baseline
3. **Iterate**: Refine detection based on findings
4. **Document**: Update detection and playbooks

## Support & Feedback

**Detection Issues**:
- Detection Engineering Team: [contact]
- SIEM Administrator: [contact]

**False Positives**:
- Report via JIRA with tag: `detection-tuning`
- Include context and justification
- Suggest exclusion criteria

**New Detection Requests**:
- Submit via JIRA (Issue Type: Detection Request)
- Include use case and threat scenario
- Provide sample data if available

---

**Repository Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
**Total Detections**: 49
**Coverage**: MITRE ATT&CK v14
# Detection Analytics & SIEM Queries

## Overview

This directory contains detection analytics, SIEM queries, and use cases for security monitoring. Each analytic is treated as a Configuration Item (CI) and linked to incidents, MITRE ATT&CK techniques, and response playbooks.

## Directory Structure

```
analytics/
├── detection-rules/        # Detection rule definitions
├── siem-queries/          # SIEM-specific query implementations
├── use-cases/             # Detection use case documentation
└── README.md              # This file
```

## Detection Analytics as Configuration Items

### Naming Convention
- **Format**: `ANALYTIC-{3-digit-ID}`
- **Example**: `ANALYTIC-001`, `ANALYTIC-042`

### Analytics Metadata

Each analytic includes:
- **Analytic ID**: Unique identifier
- **Name**: Descriptive name
- **Description**: What it detects
- **Data Sources**: Required log sources
- **MITRE ATT&CK Mapping**: Tactics and techniques
- **Severity**: Alert severity when triggered
- **False Positive Rate**: Expected FP rate
- **JIRA Use Case**: Associated use case(s)
- **Response Playbook**: KB article link
- **Detection Logic**: Query/rule logic
- **Tuning Notes**: Known FPs and tuning guidance

## Detection Analytics Catalog

### ANALYTIC-001: Suspicious PowerShell Execution
**Description**: Detects potentially malicious PowerShell commands with obfuscation or encoded commands

**MITRE ATT&CK**:
- Tactic: Execution (TA0002)
- Technique: Command and Scripting Interpreter: PowerShell (T1059.001)

**Data Sources**:
- Windows Event Logs (Event ID 4104, 4103)
- Sysmon (Event ID 1)
- PowerShell logs

**Severity**: High

**Detection Logic**:
```
index=windows EventCode=4104 OR EventCode=4103
| eval suspicious_patterns=if(
    match(ScriptBlockText, "(?i)(bypass|noprofile|encoded|invoke-expression|downloadstring|iex|hidden)"),
    1, 0
  )
| where suspicious_patterns=1
| stats count by Computer, User, ScriptBlockText
```

**False Positives**:
- Legitimate admin scripts
- Software deployment tools
- Configuration management

**Tuning Guidance**:
- Whitelist known admin accounts
- Whitelist approved script hashes
- Exclude system accounts

**Response Playbook**: KB-0023 (PowerShell Malware Response)

**Use Cases**: UC-002 (Malware Execution), UC-007 (Suspicious Script Execution)

---

### ANALYTIC-002: Brute Force Login Attempts
**Description**: Detects multiple failed login attempts from same source

**MITRE ATT&CK**:
- Tactic: Credential Access (TA0006)
- Technique: Brute Force (T1110)

**Data Sources**:
- Windows Event Logs (Event ID 4625)
- VPN logs
- Web application logs

**Severity**: Medium

**Detection Logic**:
```
index=windows EventCode=4625
| stats count by src_ip, user
| where count > 10
| table src_ip, user, count
```

**Threshold**: 10 failed attempts within 5 minutes

**False Positives**:
- Locked out users
- Password expiration
- Forgotten passwords

**Tuning Guidance**:
- Adjust threshold based on environment
- Whitelist known IPs
- Exclude service accounts

**Response Playbook**: KB-0031 (Account Lockout Investigation)

**Use Cases**: UC-001 (Suspicious Login Activity), UC-003 (External Attack)

---

### ANALYTIC-003: LSASS Memory Access
**Description**: Detects unauthorized access to LSASS process memory (credential dumping)

**MITRE ATT&CK**:
- Tactic: Credential Access (TA0006)
- Technique: OS Credential Dumping: LSASS Memory (T1003.001)

**Data Sources**:
- Sysmon (Event ID 10: Process Access)
- EDR alerts

**Severity**: Critical

**Detection Logic**:
```
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| where NOT (SourceImage IN ("*\\svchost.exe", "*\\csrss.exe", "*\\wininit.exe"))
| table _time, Computer, SourceImage, SourceProcessId, GrantedAccess
```

**False Positives**:
- Legitimate security tools
- AV/EDR agents
- System processes

**Tuning Guidance**:
- Whitelist known security tools by hash
- Exclude signed Microsoft binaries
- Monitor GrantedAccess permissions

**Response Playbook**: KB-0042 (Credential Dumping Response)

**Use Cases**: UC-004 (Credential Theft)

**RE&CT Actions**: RA3101 (Disable Compromised Credentials)

---

### ANALYTIC-004: Lateral Movement via WMI
**Description**: Detects lateral movement attempts using WMI

**MITRE ATT&CK**:
- Tactic: Lateral Movement (TA0008), Execution (TA0002)
- Technique: Windows Management Instrumentation (T1047)

**Data Sources**:
- Sysmon (Event ID 1: Process Creation)
- Windows Event Logs (Event ID 4688)
- Network logs (port 135, 5985)

**Severity**: High

**Detection Logic**:
```
index=sysmon EventCode=1 (Image="*\\wmic.exe" OR ParentImage="*\\wmiprvse.exe")
| where CommandLine="*/node:*" OR CommandLine="*process call create*"
| table _time, Computer, User, CommandLine, ParentProcessId
```

**False Positives**:
- Admin remote management
- System management tools
- Orchestration platforms

**Tuning Guidance**:
- Whitelist approved admin accounts
- Exclude known management tools
- Baseline normal WMI activity

**Response Playbook**: KB-0045 (Lateral Movement Response)

**Use Cases**: UC-005 (Lateral Movement Detection)

---

### ANALYTIC-005: Data Exfiltration to Cloud Storage
**Description**: Detects large data uploads to cloud storage services

**MITRE ATT&CK**:
- Tactic: Exfiltration (TA0010)
- Technique: Exfiltration to Cloud Storage (T1567.002)

**Data Sources**:
- Proxy logs
- Firewall logs
- DLP logs

**Severity**: High

**Detection Logic**:
```
index=proxy
| where url IN ("*dropbox.com*", "*drive.google.com*", "*onedrive.com*", "*box.com*")
| stats sum(bytes_out) as total_bytes by src_ip, user
| where total_bytes > 100000000
| table _time, src_ip, user, total_bytes
```

**Threshold**: 100 MB uploaded within 1 hour

**False Positives**:
- Legitimate cloud usage
- Approved file sharing
- Backups

**Tuning Guidance**:
- Whitelist approved users/departments
- Adjust threshold based on business needs
- Correlate with DLP alerts

**Response Playbook**: KB-0051 (Data Exfiltration Response)

**Use Cases**: UC-006 (Data Exfiltration), UC-008 (Insider Threat)

---

### ANALYTIC-006: Suspicious Process Execution from Temp Directories
**Description**: Detects executables running from temporary directories

**MITRE ATT&CK**:
- Tactic: Execution (TA0002)
- Technique: User Execution (T1204)

**Data Sources**:
- Sysmon (Event ID 1)
- Windows Event Logs (Event ID 4688)

**Severity**: Medium

**Detection Logic**:
```
index=sysmon EventCode=1
| where Image="*\\Temp\\*" OR Image="*\\AppData\\Local\\Temp\\*"
| table _time, Computer, User, Image, CommandLine, ParentImage
```

**False Positives**:
- Software installers
- Update processes
- Temporary tools

**Tuning Guidance**:
- Whitelist known installers by hash
- Exclude signed executables
- Baseline normal temporary execution

**Response Playbook**: KB-0027 (Malware Execution Response)

**Use Cases**: UC-002 (Malware Execution)

---

### ANALYTIC-007: Scheduled Task Creation
**Description**: Detects creation of scheduled tasks for persistence

**MITRE ATT&CK**:
- Tactic: Persistence (TA0003), Privilege Escalation (TA0004)
- Technique: Scheduled Task/Job (T1053.005)

**Data Sources**:
- Windows Event Logs (Event ID 4698)
- Sysmon (Event ID 1)

**Severity**: Medium

**Detection Logic**:
```
index=windows EventCode=4698
| table _time, Computer, TaskName, SubjectUserName, Command
```

**False Positives**:
- Legitimate admin tasks
- Software deployment
- System updates

**Tuning Guidance**:
- Whitelist known task names
- Exclude system accounts
- Monitor for suspicious task actions

**Response Playbook**: KB-0033 (Persistence Investigation)

**Use Cases**: UC-009 (Persistence Detection)

---

### ANALYTIC-008: Registry Run Key Modification
**Description**: Detects modifications to registry run keys for persistence

**MITRE ATT&CK**:
- Tactic: Persistence (TA0003), Privilege Escalation (TA0004)
- Technique: Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)

**Data Sources**:
- Sysmon (Event ID 13: Registry value set)
- Windows Event Logs

**Severity**: High

**Detection Logic**:
```
index=sysmon EventCode=13
| where TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
   OR TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"
| table _time, Computer, User, TargetObject, Details
```

**False Positives**:
- Software installation
- System configuration
- Legitimate startup programs

**Tuning Guidance**:
- Whitelist known applications
- Exclude signed binaries
- Baseline normal registry changes

**Response Playbook**: KB-0033 (Persistence Investigation)

**Use Cases**: UC-009 (Persistence Detection)

---

### ANALYTIC-009: Kerberoasting Detection
**Description**: Detects Kerberoasting attacks (TGS requests for service accounts)

**MITRE ATT&CK**:
- Tactic: Credential Access (TA0006)
- Technique: Steal or Forge Kerberos Tickets: Kerberoasting (T1558.003)

**Data Sources**:
- Windows Event Logs (Event ID 4769)
- Domain Controller logs

**Severity**: High

**Detection Logic**:
```
index=windows EventCode=4769
| where TicketEncryptionType="0x17"
| stats count by ServiceName, TargetUserName, IpAddress
| where count > 5
| table _time, ServiceName, TargetUserName, IpAddress, count
```

**False Positives**:
- Legitimate service requests
- Application behavior
- Service account enumeration

**Tuning Guidance**:
- Adjust threshold based on environment
- Whitelist known applications
- Monitor for multiple TGS requests

**Response Playbook**: KB-0046 (Kerberoasting Response)

**Use Cases**: UC-004 (Credential Theft)

---

### ANALYTIC-010: Phishing Email Detection
**Description**: Detects phishing emails based on indicators

**MITRE ATT&CK**:
- Tactic: Initial Access (TA0001)
- Technique: Phishing (T1566)

**Data Sources**:
- Email gateway logs
- Email security appliance
- Office 365 logs

**Severity**: Medium

**Detection Logic**:
```
index=email
| where subject="*urgent*" OR subject="*verify*" OR subject="*suspended*"
| where sender_domain NOT IN (approved_domains)
| table _time, sender, recipient, subject, attachment_count
```

**False Positives**:
- Legitimate urgent emails
- External partners
- Customer communications

**Tuning Guidance**:
- Whitelist trusted domains
- Enhance with URL analysis
- Correlate with user reports

**Response Playbook**: KB-0011 (Phishing Response)

**Use Cases**: UC-010 (Phishing Detection)

---

## Analytics Development Lifecycle

### 1. Identification
- Identify detection gap
- Map to MITRE ATT&CK
- Define detection objectives

### 2. Design
- Define data sources
- Write detection logic
- Establish thresholds
- Document expected outputs

### 3. Development
- Implement query/rule
- Test with sample data
- Validate accuracy
- Optimize performance

### 4. Testing
- Test in dev environment
- Validate against known incidents
- Measure false positive rate
- Adjust thresholds

### 5. Deployment
- Deploy to production SIEM
- Configure alerting
- Create JIRA integration
- Link to playbook

### 6. Baseline & Tuning
- Monitor for 2 weeks
- Document false positives
- Tune thresholds
- Update exclusions

### 7. Maintenance
- Weekly: Review alert volume
- Monthly: Validate effectiveness
- Quarterly: Update for new TTPs
- Annually: Full analytic review

## Analytics Quality Metrics

### Effectiveness Metrics
- **True Positive Rate**: % of alerts that are real threats
- **False Positive Rate**: % of alerts that are benign
- **Detection Rate**: % of incidents detected by analytic
- **Time to Detect**: Avg time from activity to alert

### Performance Metrics
- **Query Performance**: Execution time
- **Resource Usage**: CPU/memory consumption
- **Data Volume**: Log volume processed
- **Alert Volume**: Alerts generated per day

### Coverage Metrics
- **MITRE ATT&CK Coverage**: % of techniques with detection
- **DeTT&CT Score**: Detection capability maturity
- **Data Source Coverage**: % of required sources available
- **Technique Detection Depth**: Multiple analytics per technique

## Integration with JIRA

### Automatic Linking
```
When: SIEM alert creates JIRA issue
Then:
  1. Parse alert name/ID
  2. Look up ANALYTIC-{ID} in catalog
  3. Populate fields:
     - Detection Analytics: ANALYTIC-{ID}
     - MITRE ATT&CK Techniques: [from analytic metadata]
     - Response Playbook: [KB link]
     - Use Case: [UC-XXX]
  4. Add comment with analytic details
```

### Analytics Dashboard
```
Widgets:
1. Alert Volume by Analytic (bar chart)
2. Top 10 Analytics by True Positives (table)
3. Analytics with Highest FP Rate (table)
4. Analytics Detection Coverage (heatmap)
5. Analytics Performance (table)
```

## Analytics Repository Structure

### Template for New Analytics

```yaml
# ANALYTIC-XXX: [Name]

## Metadata
- Analytic ID: ANALYTIC-XXX
- Name: [Descriptive Name]
- Version: 1.0
- Created: YYYY-MM-DD
- Last Updated: YYYY-MM-DD
- Author: [Team/Individual]
- Status: [Development | Testing | Production | Deprecated]

## Detection Details
- Description: [What it detects]
- Data Sources: [Required logs]
- SIEM Platform: [Splunk | Sentinel | ELK | etc.]
- Query Language: [SPL | KQL | etc.]

## MITRE ATT&CK Mapping
- Tactics: [TA codes]
- Techniques: [T codes]
- Sub-techniques: [T codes with .xxx]

## Severity & Priority
- Alert Severity: [Critical | High | Medium | Low]
- Business Impact: [High | Medium | Low]
- JIRA Priority: [P1 | P2 | P3 | P4]

## Detection Logic
```[query language]
[detection query]
```

## Configuration
- Threshold: [values]
- Lookback Period: [time]
- Aggregation: [method]
- Schedule: [frequency]

## False Positives
- Expected FP Rate: [percentage]
- Common False Positives:
  1. [FP scenario 1]
  2. [FP scenario 2]
- Tuning Guidance:
  - [Tuning tip 1]
  - [Tuning tip 2]

## Response
- Response Playbook: KB-XXX
- JIRA Use Cases: UC-XXX
- RE&CT Actions: RA-XXXX
- Recommended Actions:
  1. [Action 1]
  2. [Action 2]

## Testing
- Test Data: [location]
- Test Results: [Pass/Fail]
- Validation Date: YYYY-MM-DD
- Validated By: [Name]

## Maintenance
- Review Frequency: [Weekly | Monthly | Quarterly]
- Last Review: YYYY-MM-DD
- Next Review: YYYY-MM-DD
- Owner: [Team/Individual]
```

## Next Steps

1. **Populate Analytics Catalog** - Document existing detections
2. **Implement CI Linking** - Connect analytics to incidents
3. **Deploy Dashboards** - Create analytics performance dashboards
4. **Establish Metrics** - Track effectiveness and coverage
5. **Continuous Improvement** - Regular review and optimization

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
