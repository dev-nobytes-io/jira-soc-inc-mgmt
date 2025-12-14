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
