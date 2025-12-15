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
│   ├── processes/                  # Process documentation
│   └── ANALYTICS-REPORTING.md      # Analytics and reporting guide
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
├── analytics/                      # Detection analytics and SIEM queries
│   ├── detection-rules/            # Detection rule definitions
│   ├── siem-queries/               # Platform-specific queries
│   ├── use-cases/                  # Detection use case documentation
│   └── README.md                   # Analytics catalog and guide
│
├── configuration-items/            # Configuration Items (CI) framework
│   ├── detection-analytics/        # Detection analytics as CIs
│   ├── knowledge-base/             # KB articles as CIs
│   ├── mitre-mappings/             # ATT&CK technique mappings
│   ├── frameworks/                 # Framework alignment data
│   └── README.md                   # CI integration guide
│
├── reference/                      # Reference materials and frameworks
│   ├── frameworks/                 # General framework documentation
│   ├── mitre-attack/               # MITRE ATT&CK integration
│   ├── react/                      # RE&CT response framework
│   ├── dettact/                    # DeTT&CT detection coverage
│   ├── nist-csf-2.0/               # NIST CSF 2.0 framework
│   └── picerl/                     # PICERL incident management
│
└── integrations/                   # Integration guides
    ├── siem/                       # SIEM platform integrations
    ├── edr/                        # EDR/XDR integrations
    └── README.md                   # Integration overview
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

### Configuration Items (CI) Integration
- **Detection Analytics as CIs**: Track detection rules like ANALYTIC-001 through incidents
- **Knowledge Base as CIs**: Link playbooks (KB-XXXX) to incidents for analytics
- **Framework Mappings**: MITRE ATT&CK, NIST CSF 2.0, PICERL, RE&CT, DeTT&CT
- **Relationship Tracking**: Chain from detection → technique → response → playbook
- **Analytics & Reporting**: Measure detection effectiveness, playbook usage, coverage gaps

### Framework Integration

#### MITRE ATT&CK
- **Tactics & Techniques**: Map incidents to ATT&CK framework
- **Coverage Tracking**: Visualize detection coverage per technique
- **ATT&CK Navigator**: Export heatmaps of observed techniques
- **Threat Intelligence**: Auto-enrich incidents with technique details

#### NIST CSF 2.0
- **Function Mapping**: Align incidents to Govern, Identify, Protect, Detect, Respond, Recover
- **Category Tracking**: Map activities to specific CSF categories (e.g., DE.CM-7, RS.MI-01)
- **Compliance Reporting**: Track CSF coverage and maturity
- **Workflow Alignment**: Auto-populate CSF fields based on incident phase

#### PICERL Framework
- **Phase Management**: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
- **Phase Duration Tracking**: Measure time in each phase
- **Maturity Metrics**: Track incident response capability improvement
- **Automated Transitions**: Auto-set phase based on workflow state

#### RE&CT Response Framework
- **Response Actions**: RA-coded procedures (RA3101: Disable credentials, RA4201: Remove malware)
- **Action Checklists**: Auto-create response task lists per phase
- **Procedure Guidance**: Step-by-step response procedures
- **Effectiveness Tracking**: Measure action completion and success rates

#### DeTT&CT Detection Coverage
- **Coverage Assessment**: Score detection capability per ATT&CK technique (0-5 scale)
- **Gap Analysis**: Identify techniques without detection
- **Maturity Tracking**: Measure overall detection program maturity
- **Visualization**: Export coverage layers to ATT&CK Navigator

### JIRA Features
- **Custom Issue Types**: Alert, Incident, Investigation, Policy Violation
- **Automated Workflows**: Triage → Investigation → Containment → Eradication → Recovery
- **Smart Enrichment**: Automatic data gathering from integrations
- **SLA Tracking**: Configurable SLAs by severity and type
- **Advanced Dashboards**: Detection coverage, framework compliance, CI analytics

### Confluence Features
- **Knowledge Base**: Centralized security documentation (KB-XXXX format)
- **Playbook Library**: Step-by-step response procedures with effectiveness ratings
- **Post-Incident Reviews**: Lessons learned templates with improvement tracking
- **Threat Intelligence**: ATT&CK mappings, threat actor profiles, campaign analysis
- **Team Runbooks**: Operational procedures linked to incidents

### Detection Analytics
- **Analytics Catalog**: ANALYTIC-XXX numbered detection rules
- **SIEM Queries**: Platform-specific implementation (Splunk, Sentinel, etc.)
- **Coverage Mapping**: Link analytics to ATT&CK techniques
- **Effectiveness Metrics**: True positive rate, MTTR, detection quality
- **Use Case Tracking**: Document detection objectives and validation

### Automation
- Auto-assignment based on incident type
- Severity escalation rules
- Framework auto-population (ATT&CK, CSF, PICERL)
- Detection analytics linking
- Knowledge base article suggestions
- RE&CT action checklist creation
- Phase duration tracking
- Playbook effectiveness prompts

## Documentation

### Core Documentation
- [JIRA Setup Guide](docs/jira/SETUP.md)
- [Configuration Items Setup](docs/jira/CONFIGURATION-ITEMS.md)
- [Analytics & Reporting Guide](docs/ANALYTICS-REPORTING.md)
- [Confluence Setup Guide](docs/confluence/SETUP.md)
- [Workflow Overview](docs/workflows/OVERVIEW.md)
- [Integration Guide](integrations/README.md)

### Configuration Items & Frameworks
- [Configuration Items Overview](configuration-items/README.md)
- [Detection Analytics Catalog](analytics/README.md)
- [Knowledge Base Integration](configuration-items/knowledge-base/README.md)
- [MITRE ATT&CK Integration](reference/mitre-attack/README.md)
- [NIST CSF 2.0 Framework](reference/nist-csf-2.0/README.md)
- [PICERL Framework](reference/picerl/README.md)
- [RE&CT Response Framework](reference/react/README.md)
- [DeTT&CT Coverage Tracking](reference/dettact/README.md)

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
