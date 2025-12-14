# SOC Case Management System - JIRA & Confluence

A comprehensive Security Operations Center (SOC) case management framework built on JIRA and Confluence for tracking, managing, and responding to cybersecurity incidents.

## Overview

This repository contains the complete framework for managing security incidents from detection through resolution using native JIRA and Confluence features. It includes automated workflows, playbooks, templates, and integration guides.

## Repository Structure

```
jira-soc-inc-mgmt/
├── docs/                           # Documentation
│   ├── jira/                       # JIRA-specific documentation
│   ├── confluence/                 # Confluence-specific documentation
│   ├── workflows/                  # Workflow diagrams and documentation
│   └── processes/                  # Process documentation
│
├── templates/                      # Templates for tickets, pages, reports
│   ├── jira/                       # JIRA issue templates
│   ├── confluence/                 # Confluence page templates
│   ├── playbooks/                  # Response playbook templates
│   └── incident-response/          # IR documentation templates
│
├── playbooks/                      # Incident response playbooks
│   ├── malware/                    # Malware incident playbooks
│   ├── phishing/                   # Phishing incident playbooks
│   ├── data-exfiltration/          # Data exfiltration playbooks
│   ├── insider-threat/             # Insider threat playbooks
│   └── compromised-account/        # Account compromise playbooks
│
├── automation/                     # Automation rules and scripts
│   ├── jira-rules/                 # JIRA automation rules
│   └── scripts/                    # Helper scripts
│
├── analytics/                      # Detection analytics (SIEM queries)
├── integrations/                   # Integration guides
└── reference/                      # Reference materials
```

## Quick Start

### Prerequisites

- JIRA Cloud or Data Center instance
- Confluence Cloud or Data Center instance
- SIEM platform (Splunk, Sentinel, etc.)
- Active Directory/Identity Provider
- Communication platform (Slack, Teams - optional)

### Setup Steps

1. **JIRA Configuration** (30 minutes)
   - Create SOC project
   - Import custom fields
   - Configure workflows
   - Set up automation rules

2. **Confluence Setup** (20 minutes)
   - Create SOC space
   - Import page templates
   - Configure permissions

3. **Integration** (15 minutes)
   - Configure SIEM → JIRA webhooks
   - Set up notification channels
   - Test end-to-end flow

See [docs/jira/SETUP.md](docs/jira/SETUP.md) for detailed instructions.

## Key Features

### JIRA Features
- **Custom Issue Types**: Alert, Incident, Investigation, Policy Violation
- **Automated Workflows**: Triage → Investigation → Containment → Resolution
- **Smart Enrichment**: Automatic data gathering from integrations
- **SLA Tracking**: Configurable SLAs by severity and type
- **Dashboards**: Real-time SOC metrics and KPIs

### Confluence Features
- **Knowledge Base**: Centralized security documentation
- **Playbook Library**: Step-by-step response procedures
- **Post-Incident Reviews**: Templates for lessons learned
- **Threat Intelligence**: Tracking and sharing threat data
- **Team Runbooks**: Operational procedures

### Automation
- Auto-assignment based on incident type
- Severity escalation rules
- Notification triggers
- Evidence collection automation
- Status synchronization

## Documentation

### Core Documentation
- [JIRA Setup Guide](docs/jira/SETUP.md)
- [Confluence Setup Guide](docs/confluence/SETUP.md)
- [Workflow Overview](docs/workflows/OVERVIEW.md)
- [Integration Guide](integrations/README.md)

### JIRA Configuration
- [Custom Fields](docs/jira/CUSTOM-FIELDS.md)
- [Issue Types & Workflows](docs/jira/ISSUE-TYPES.md)
- [Automation Rules](automation/jira-rules/README.md)
- [Dashboards & Reports](docs/jira/DASHBOARDS.md)

### Confluence Setup
- [Space Structure](docs/confluence/SPACE-STRUCTURE.md)
- [Page Templates](templates/confluence/README.md)
- [Permission Scheme](docs/confluence/PERMISSIONS.md)

### Incident Response
- [Playbook Index](playbooks/README.md)
- [Severity Classification](docs/processes/SEVERITY.md)
- [Escalation Procedures](docs/processes/ESCALATION.md)
- [Communication Plan](docs/processes/COMMUNICATION.md)

## Playbooks

Detailed playbooks for common incident types:

- [Phishing Response](playbooks/phishing/PLAYBOOK.md)
- [Malware Incident](playbooks/malware/PLAYBOOK.md)
- [Compromised Account](playbooks/compromised-account/PLAYBOOK.md)
- [Data Exfiltration](playbooks/data-exfiltration/PLAYBOOK.md)
- [Insider Threat](playbooks/insider-threat/PLAYBOOK.md)

## JIRA Project Structure

### Issue Types

1. **Alert** - Automated detection from SIEM/security tools
2. **Incident** - Confirmed security incident requiring response
3. **Investigation** - Proactive threat hunting or research
4. **Policy Violation** - Security policy breach
5. **Vulnerability** - Identified security weakness

### Workflows

```
Alert Workflow:
New → Triage → Investigation → Escalate to Incident / False Positive → Closed

Incident Workflow:
New → Triage → Investigation → Containment → Eradication → Recovery → Closed

Investigation Workflow:
New → In Progress → Analysis → Report → Closed
```

### Custom Fields

- Incident Severity (Critical, High, Medium, Low, Info)
- Incident Category (Malware, Phishing, Data Loss, etc.)
- Affected Assets
- Indicators of Compromise (IOCs)
- MITRE ATT&CK Tactics/Techniques
- Detection Source
- Assigned Team
- Evidence Links
- Response Actions Taken
- Root Cause

See [docs/jira/CUSTOM-FIELDS.md](docs/jira/CUSTOM-FIELDS.md) for complete field definitions.

## Confluence Space Structure

```
SOC Operations
├── 📁 Playbooks
│   ├── Incident Response Procedures
│   ├── Detection Use Cases
│   └── Escalation Paths
│
├── 📁 Knowledge Base
│   ├── Threat Intelligence
│   ├── Tool Documentation
│   └── System Architecture
│
├── 📁 Post-Incident Reviews
│   ├── 2024 Incidents
│   └── Lessons Learned
│
├── 📁 Metrics & Reporting
│   ├── Monthly Reports
│   └── KPI Dashboards
│
└── 📁 Team Operations
    ├── On-Call Schedule
    ├── Training Materials
    └── Contact Lists
```

## Integration Points

### SIEM → JIRA
- Automated alert creation
- Enrichment data population
- Bi-directional status updates

### JIRA → Communication (Slack/Teams)
- Real-time incident notifications
- Status change updates
- Assignment notifications

### JIRA ↔ Confluence
- Linked playbooks
- Automatic post-incident page creation
- Knowledge base references

See [integrations/README.md](integrations/README.md) for configuration details.

## Metrics & KPIs

Track SOC effectiveness with built-in dashboards:

- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Mean Time to Resolve (MTTR)
- True Positive Rate
- False Positive Rate
- Incident Volume by Category
- SLA Compliance
- Escalation Rate

## Deployment Timeline

### Week 1: Foundation
- ✅ JIRA project setup
- ✅ Basic workflows configured
- ✅ Core custom fields added
- ✅ Team permissions set

### Week 2: Integration
- ✅ SIEM integration configured
- ✅ Alert routing functional
- ✅ Basic automation rules active
- ✅ Dashboards deployed

### Week 3: Enhancement
- ✅ Confluence space populated
- ✅ Playbooks documented
- ✅ Advanced automation deployed
- ✅ Team training completed

### Week 4: Optimization
- ✅ Tune alert thresholds
- ✅ Refine workflows
- ✅ Gather feedback
- ✅ Continuous improvement

## Best Practices

1. **Consistent Categorization**: Use standardized incident categories
2. **Detailed Documentation**: Document all investigation steps in JIRA
3. **Evidence Preservation**: Link all evidence to tickets
4. **Timely Updates**: Update ticket status in real-time
5. **Post-Incident Reviews**: Complete PIRs for all major incidents
6. **Knowledge Sharing**: Document lessons learned in Confluence
7. **Regular Training**: Keep playbooks updated and team trained

## Support & Maintenance

### Regular Tasks
- Weekly: Review open incidents, update dashboards
- Monthly: Generate metrics reports, update playbooks
- Quarterly: Review and optimize workflows
- Annually: Full framework assessment

### Troubleshooting
- Check [docs/jira/TROUBLESHOOTING.md](docs/jira/TROUBLESHOOTING.md)
- Review automation rule logs in JIRA
- Verify integration webhook configurations

## Contributing

To add new playbooks or improve existing documentation:

1. Create new content in appropriate directory
2. Follow existing template structure
3. Update relevant README files
4. Test with actual scenarios
5. Document any new fields or workflows

## Version History

- **v1.0** - Initial framework release
- Includes core JIRA setup, Confluence templates, and 5 main playbooks

## License

Internal use only - [Your Organization Name]

## Contact

SOC Team Lead: [contact information]
JIRA Administrator: [contact information]
Security Engineering: [contact information]

---

**Last Updated**: 2025-12-14
**Maintained By**: SOC Team
