# SOC Incident Response Playbooks

## Overview

This directory contains incident response playbooks for common security incidents. Each playbook provides step-by-step procedures for detection, investigation, containment, eradication, and recovery.

## Available Playbooks

### High-Priority Incidents

1. **[Phishing/Social Engineering](phishing/PLAYBOOK.md)**
   - Email-based attacks
   - Credential harvesting
   - Business email compromise (BEC)
   - Severity: Varies (Low to Critical)

2. **[Malware/Ransomware](malware/PLAYBOOK.md)**
   - Malware infections
   - Ransomware attacks
   - Wiper malware
   - Severity: High to Critical

3. **[Compromised Account](compromised-account/PLAYBOOK.md)**
   - Stolen credentials
   - Unauthorized access
   - Account takeover
   - Severity: Medium to Critical

4. **[Data Exfiltration](data-exfiltration/PLAYBOOK.md)**
   - Unauthorized data transfer
   - Data theft
   - Intellectual property loss
   - Severity: High to Critical

5. **[Insider Threat](insider-threat/PLAYBOOK.md)**
   - Malicious insider activity
   - Policy violations
   - Privilege abuse
   - Severity: Medium to Critical

## Playbook Structure

Each playbook follows a standard format:

```
1. Overview & Classification
2. Detection & Triage
3. Investigation
4. Containment
5. Eradication
6. Recovery
7. Post-Incident Activities
8. Escalation Criteria
9. Communication Plan
10. Tools & Resources
```

## How to Use These Playbooks

### During an Active Incident

1. **Identify Incident Type**: Match alert/incident to appropriate playbook
2. **Assess Severity**: Use classification criteria to determine priority
3. **Create JIRA Ticket**: Use incident type as template
4. **Follow Phases**: Work through each phase sequentially
5. **Document Actions**: Record all steps taken in JIRA
6. **Escalate if Needed**: Follow escalation criteria
7. **Complete PIR**: Use post-incident template

### For Training & Exercises

1. Select relevant playbook
2. Create simulated scenario
3. Walk through procedures
4. Identify gaps or improvements
5. Update playbook as needed

### For Continuous Improvement

1. Review after each incident
2. Document what worked / didn't work
3. Update playbooks quarterly
4. Incorporate lessons learned
5. Share updates with team

## Severity Classification Guide

### Critical (P1)
- Widespread impact
- Critical systems affected
- Data breach confirmed
- Ransomware encryption
- Active data exfiltration
- C-level executive compromise

**Response Time**: 15 minutes
**Resolution Time**: 4 hours
**Escalation**: Immediate to IR Team Lead

### High (P2)
- Multiple systems affected
- Sensitive data at risk
- Lateral movement detected
- Malware on critical system
- VIP user compromised

**Response Time**: 1 hour
**Resolution Time**: 24 hours
**Escalation**: To IR Team if unresolved in 2 hours

### Medium (P3)
- Single system affected
- Low-value data at risk
- Contained malware
- Standard user phished
- Policy violation

**Response Time**: 4 hours
**Resolution Time**: 72 hours
**Escalation**: To Team Lead if unresolved in 24 hours

### Low (P4)
- Minimal impact
- Unsuccessful attack
- Minor policy violation
- Single false alarm

**Response Time**: 8 hours
**Resolution Time**: 1 week
**Escalation**: Not required unless pattern emerges

### Informational (P5)
- No immediate threat
- Awareness/intelligence
- Suspicious but benign
- Tuning required

**Response Time**: Best effort
**Resolution Time**: N/A
**Escalation**: Not required

## Common Response Actions

### Containment Actions

**Network Isolation**:
```bash
# Disable network adapter (Windows)
netsh interface set interface "Ethernet" admin=disable

# Disable network adapter (Linux)
sudo ifconfig eth0 down

# Firewall block (Windows)
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
```

**Account Lockout**:
```powershell
# Disable AD account
Disable-ADAccount -Identity username

# Reset password
Set-ADAccountPassword -Identity username -Reset

# Revoke sessions
Revoke-AzureADUserAllRefreshToken -ObjectId user@domain.com
```

**Process Termination**:
```powershell
# Kill process by name
Stop-Process -Name "malicious" -Force

# Kill process by PID
Stop-Process -Id 1234 -Force
```

### Evidence Collection

**Windows System**:
```powershell
# Collect system info
systeminfo > C:\temp\systeminfo.txt

# List running processes
Get-Process | Export-Csv C:\temp\processes.csv

# Export event logs
wevtutil epl Security C:\temp\Security.evtx
wevtutil epl System C:\temp\System.evtx

# Get network connections
netstat -ano > C:\temp\netstat.txt

# List scheduled tasks
Get-ScheduledTask | Export-Csv C:\temp\tasks.csv
```

**Linux System**:
```bash
# System info
uname -a > /tmp/sysinfo.txt
ps aux > /tmp/processes.txt

# Network connections
netstat -tunapl > /tmp/netstat.txt
ss -tunapl > /tmp/ss.txt

# Auth logs
cp /var/log/auth.log /tmp/auth.log

# Recently modified files
find / -type f -mtime -1 > /tmp/recent_files.txt
```

## Integration with JIRA

### Creating Incident from Playbook

1. Navigate to SOC project
2. Create issue → Select incident type
3. Playbook field auto-populated with link
4. Fill custom fields based on playbook guidance
5. Follow workflow states aligned with playbook phases

### Linking Playbooks

All playbooks are:
- Stored in Confluence
- Linked from JIRA automation
- Referenced in alert templates
- Accessible via quick links

## Team Responsibilities

### Tier 1 Analyst
- Initial triage using playbooks
- Follow detection & triage sections
- Escalate based on criteria
- Document in JIRA

### Tier 2 Analyst
- Full investigation using playbooks
- Execute containment actions
- Coordinate with IT/business units
- Update playbooks with findings

### Tier 3 / Incident Responder
- Handle complex incidents
- Lead eradication and recovery
- Coordinate external resources
- Conduct post-incident reviews
- Update and improve playbooks

### SOC Lead
- Oversee all incidents
- Approve critical actions
- Manage escalations
- Review playbook effectiveness
- Ensure continuous improvement

## Playbook Maintenance

### Review Frequency

- **After Each Critical Incident**: Immediate review
- **Monthly**: Review most-used playbooks
- **Quarterly**: Full playbook inventory review
- **Annually**: Complete overhaul and validation

### Update Process

1. Identify need for update (incident, exercise, threat change)
2. Draft changes in working copy
3. Review with team
4. Test in exercise if significant changes
5. Approve and publish
6. Notify team of changes
7. Archive old version

### Version Control

- All playbooks versioned in Confluence
- Major version (1.0, 2.0): Significant changes
- Minor version (1.1, 1.2): Minor updates
- Version history maintained
- Change log included in each playbook

## Metrics & Improvement

Track these metrics per playbook:

- **Usage Frequency**: How often playbook is used
- **Effectiveness**: Incidents resolved successfully
- **Time Metrics**: Average time per phase
- **Accuracy**: Correct playbook selection rate
- **Completeness**: Steps followed vs. skipped
- **Outcome**: Incident fully resolved vs. escalated

Use metrics to:
- Identify high-value playbooks
- Find gaps in coverage
- Optimize frequently-used procedures
- Justify resource allocation

## Training & Exercises

### New Analyst Training

Week 1: Read all playbooks
Week 2: Walk through 2-3 scenarios
Week 3: Shadow experienced analyst
Week 4: Handle incidents with oversight

### Regular Exercises

- Monthly: Tabletop exercise with one playbook
- Quarterly: Full incident simulation
- Annually: Red team / purple team exercise

### Exercise Scenarios

Located in `/reference/exercise-scenarios/`

Each scenario includes:
- Incident description
- Expected playbook usage
- Success criteria
- Evaluation rubric

## Related Documentation

- [JIRA Setup Guide](../docs/jira/SETUP.md) - Configure JIRA for playbook integration
- [Confluence Setup](../docs/confluence/SETUP.md) - Publish playbooks to Confluence
- [Escalation Procedures](../docs/processes/ESCALATION.md) - When and how to escalate
- [Communication Plan](../docs/processes/COMMUNICATION.md) - Stakeholder notifications
- [Evidence Handling](../docs/processes/EVIDENCE.md) - Proper evidence collection

## Quick Reference Card

Print this for SOC analysts:

```
┌────────────────────────────────────────────────┐
│         SOC PLAYBOOK QUICK REFERENCE           │
├────────────────────────────────────────────────┤
│ 1. Phishing → phishing/PLAYBOOK.md             │
│ 2. Malware → malware/PLAYBOOK.md               │
│ 3. Compromised Account → compromised-account/  │
│ 4. Data Exfiltration → data-exfiltration/      │
│ 5. Insider Threat → insider-threat/            │
├────────────────────────────────────────────────┤
│ CRITICAL INCIDENT CRITERIA:                    │
│ • Multiple systems impacted                    │
│ • Critical systems affected                    │
│ • Confirmed data breach                        │
│ • Active ransomware                            │
│ • C-level compromise                           │
│                                                │
│ → ESCALATE IMMEDIATELY TO IR LEAD              │
├────────────────────────────────────────────────┤
│ RESPONSE TIMES:                                │
│ P1 Critical: 15 min response, 4 hr resolve     │
│ P2 High: 1 hr response, 24 hr resolve          │
│ P3 Medium: 4 hr response, 72 hr resolve        │
│ P4 Low: 8 hr response, 1 wk resolve            │
├────────────────────────────────────────────────┤
│ ALWAYS:                                        │
│ ✓ Create JIRA ticket                           │
│ ✓ Follow playbook phases                       │
│ ✓ Document all actions                         │
│ ✓ Preserve evidence                            │
│ ✓ Escalate when needed                         │
└────────────────────────────────────────────────┘
```

## Support

**Questions about playbooks?**
- SOC Team Lead: [contact]
- Incident Response Team: [contact]
- Playbook feedback: [feedback channel]

**Emergency contacts**:
- SOC Lead (24/7): [contact]
- IR Team Lead (24/7): [contact]
- CISO: [contact]

---

**Playbook Library Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Operations Team
