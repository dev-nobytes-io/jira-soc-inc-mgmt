# SOC Workflow Overview

## Overview

This document describes the workflows used in the SOC JIRA project for managing security alerts, incidents, and investigations.

## Workflow Types

The SOC project uses different workflows for different issue types:

1. **Alert Workflow** - For automated security alerts
2. **Incident Workflow** - For confirmed security incidents
3. **Investigation Workflow** - For proactive threat hunting
4. **Policy Violation Workflow** - For policy breaches
5. **Vulnerability Workflow** - For identified vulnerabilities

---

## Alert Workflow

### Purpose
Handle automated security alerts from detection systems (SIEM, EDR, email gateway, etc.)

### States

```
┌──────┐     ┌────────┐     ┌──────────────┐     ┌──────────┐     ┌────────┐
│ New  │────▶│ Triage │────▶│ Investigation│────▶│ Escalated│────▶│ Closed │
└──────┘     └────────┘     └──────────────┘     └──────────┘     └────────┘
                │                   │                                  ▲
                │                   │                                  │
                │                   ▼                                  │
                │            ┌─────────────┐                           │
                └───────────▶│    False    │───────────────────────────┘
                             │  Positive   │
                             └─────────────┘
```

**States:**

1. **New**: Initial state when alert is created
   - Auto-assigned based on category
   - SLA clock starts
   - Awaiting analyst review

2. **Triage**: Analyst actively reviewing alert
   - Verify it's not a false positive
   - Gather initial context
   - Determine severity
   - Decision point: True positive or false positive?

3. **Investigation**: Active investigation of true positive
   - Collect evidence
   - Determine scope
   - Identify root cause
   - Decision point: Escalate to incident or close?

4. **Escalated**: Promoted to full incident
   - New incident ticket created
   - Alert linked to incident
   - Transitions to Closed

5. **False Positive**: Determined to be benign
   - Require "False Positive Reason"
   - Auto-creates tuning task for detection team
   - Transitions to Closed

6. **Closed**: Final state
   - All work completed
   - Metrics calculated

### Transitions

| From | To | Transition Name | Required Fields | Who Can Execute |
|------|----|----|----|----|
| New | Triage | Start Triage | - | SOC Analyst |
| Triage | Investigation | Investigate | - | SOC Analyst |
| Triage | False Positive | Mark False Positive | False Positive Reason | SOC Analyst |
| Investigation | Escalated | Escalate to Incident | - | SOC Analyst |
| Investigation | False Positive | Mark False Positive | False Positive Reason | SOC Analyst |
| False Positive | Closed | Close | Comments | SOC Analyst |
| Escalated | Closed | Close | Comments | SOC Analyst |

### SLA Targets

| Severity | Time to Triage | Time to Resolution |
|----------|----------------|-------------------|
| Critical | 15 minutes | 4 hours |
| High | 1 hour | 24 hours |
| Medium | 4 hours | 72 hours |
| Low | 8 hours | 1 week |

### Automation Triggers

- **On Create**: Auto-assign based on category
- **Triage → Investigation**: Add investigation checklist comment
- **Any → False Positive**: Create detection tuning task
- **Investigation → Escalated**: Create linked incident ticket
- **SLA Approaching**: Send notifications

---

## Incident Workflow

### Purpose
Manage confirmed security incidents requiring full response

### States

```
┌──────┐     ┌────────┐     ┌──────────────┐     ┌─────────────┐
│ New  │────▶│ Triage │────▶│ Investigation│────▶│ Containment │
└──────┘     └────────┘     └──────────────┘     └─────────────┘
                                                         │
                                                         ▼
┌────────┐     ┌───────────────┐     ┌──────────┐     ┌────────────┐
│ Closed │◀────│ Post-Incident │◀────│ Recovery │◀────│ Eradication│
└────────┘     └───────────────┘     └──────────┘     └────────────┘
     ▲
     │
     │         ┌────────┐
     └─────────│ Triage │ (Reopen)
               └────────┘
```

**States:**

1. **New**: Incident created (from escalated alert or direct report)
   - High severity gets immediate attention
   - Incident commander assigned (for Critical)

2. **Triage**: Initial assessment
   - Confirm incident details
   - Assess severity and scope
   - Activate response team
   - Brief stakeholders

3. **Investigation**: Understand the incident
   - Determine root cause
   - Identify affected systems/data
   - Collect evidence
   - Map to MITRE ATT&CK

4. **Containment**: Stop the spread
   - Isolate affected systems
   - Block malicious IPs/domains
   - Disable compromised accounts
   - Prevent further damage

5. **Eradication**: Remove the threat
   - Delete malware
   - Close attack vectors
   - Patch vulnerabilities
   - Reset credentials

6. **Recovery**: Restore operations
   - Bring systems back online
   - Verify security
   - Resume normal operations
   - Enhanced monitoring

7. **Post-Incident**: Document and learn
   - Complete Post-Incident Review (PIR)
   - Update playbooks
   - Implement improvements
   - Share lessons learned

8. **Closed**: Incident fully resolved
   - All tasks completed
   - PIR approved
   - Metrics recorded

### Transitions

| From | To | Transition Name | Required Fields | Who Can Execute |
|------|----|----|----|----|
| New | Triage | Start Triage | Incident Severity | SOC Lead |
| Triage | Investigation | Begin Investigation | - | Incident Responder |
| Investigation | Containment | Start Containment | Response Actions | Incident Responder |
| Containment | Eradication | Begin Eradication | - | Incident Responder |
| Eradication | Recovery | Start Recovery | - | Incident Responder |
| Recovery | Post-Incident | Begin Post-Incident | Evidence Links | Incident Responder |
| Post-Incident | Closed | Close Incident | Root Cause, PIR Link | SOC Lead |
| Closed | Triage | Reopen | Comments | SOC Lead |

### SLA Targets

| Severity | Time to Containment | Time to Resolution |
|----------|---------------------|-------------------|
| Critical | 30 minutes | 4 hours |
| High | 2 hours | 24 hours |
| Medium | 8 hours | 72 hours |
| Low | 24 hours | 1 week |

### Required Fields by Phase

**Investigation Phase:**
- Incident Category
- Affected Assets
- Indicators of Compromise
- MITRE ATT&CK Tactics

**Containment Phase:**
- Response Actions
- Evidence Links

**Post-Incident Phase:**
- Root Cause
- PIR Link (Confluence)
- Lessons Learned

### Automation Triggers

- **On Create (Critical)**: Notify CISO, create war room, page on-call
- **Investigation**: Add evidence collection checklist
- **Containment**: Notify affected system owners
- **Post-Incident**: Create PIR page in Confluence, schedule review meeting
- **Closed**: Generate metrics, archive evidence

---

## Investigation Workflow

### Purpose
Track proactive threat hunting and security research activities

### States

```
┌──────┐     ┌─────────────┐     ┌──────────┐     ┌────────┐     ┌────────┐
│ New  │────▶│ In Progress │────▶│ Analysis │────▶│ Report │────▶│ Closed │
└──────┘     └─────────────┘     └──────────┘     └────────┘     └────────┘
```

**States:**

1. **New**: Investigation request created
   - Hypothesis documented
   - Scope defined

2. **In Progress**: Active hunting
   - Query logs
   - Search for IOCs
   - Analyze patterns
   - Document findings

3. **Analysis**: Interpreting results
   - Determine if threats found
   - Assess risk
   - Recommend actions

4. **Report**: Document findings
   - Create threat hunting report
   - Present to team
   - Create action items

5. **Closed**: Investigation complete
   - Report published
   - Action items tracked separately
   - Knowledge base updated

### Transitions

| From | To | Transition Name | Who Can Execute |
|------|----|----|---|
| New | In Progress | Start Investigation | Threat Hunter |
| In Progress | Analysis | Begin Analysis | Threat Hunter |
| Analysis | Report | Create Report | Threat Hunter |
| Report | Closed | Publish Report | SOC Lead |

### Deliverables

- Threat hunting report (Confluence)
- IOC list (if threats found)
- Detection rule improvements
- Playbook updates

---

## Policy Violation Workflow

### Purpose
Track security policy violations and compliance issues

### States

```
┌──────┐     ┌────────┐     ┌──────────────┐     ┌────────────┐     ┌────────┐
│ New  │────▶│ Review │────▶│ Investigation│────▶│ Remediation│────▶│ Closed │
└──────┘     └────────┘     └──────────────┘     └────────────┘     └────────┘
                │
                │
                ▼
           ┌──────────┐
           │ Dismissed│────────────────────────────────────────────────┘
           └──────────┘
```

**States:**

1. **New**: Policy violation detected
2. **Review**: Compliance team reviews
3. **Investigation**: If needed, investigate details
4. **Remediation**: Corrective actions taken
5. **Dismissed**: Not a real violation
6. **Closed**: Violation resolved

### Required Actions

- Document policy violated
- Identify responsible party
- Determine intentional vs. accidental
- Apply appropriate response (training, discipline, etc.)
- Update policies if needed

---

## Vulnerability Workflow

### Purpose
Track identified vulnerabilities and remediation

### States

```
┌──────┐     ┌──────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌────────┐
│ New  │────▶│ Assessed │────▶│ Planned │────▶│ In Progress│────▶│ Verified│────▶│ Closed │
└──────┘     └──────────┘     └─────────┘     └──────────┘     └─────────┘     └────────┘
                │
                │
                ▼
           ┌──────────┐
           │ Accepted │────────────────────────────────────────────────────────────┘
           │   Risk   │
           └──────────┘
```

**States:**

1. **New**: Vulnerability identified
2. **Assessed**: Risk scored (CVSS)
3. **Planned**: Remediation scheduled
4. **In Progress**: Patch/fix being applied
5. **Verified**: Fix confirmed
6. **Accepted Risk**: Risk accepted (with justification)
7. **Closed**: Vulnerability remediated

### SLA Targets (by CVSS)

| CVSS Score | Severity | Time to Remediate |
|------------|----------|-------------------|
| 9.0-10.0 | Critical | 7 days |
| 7.0-8.9 | High | 30 days |
| 4.0-6.9 | Medium | 90 days |
| 0.1-3.9 | Low | 180 days |

---

## Workflow Best Practices

### General Guidelines

1. **Keep Status Current**: Update ticket status as work progresses
2. **Document Actions**: Add comments for all significant actions
3. **Link Related Issues**: Connect related alerts, incidents, investigations
4. **Follow Playbooks**: Reference and follow documented playbooks
5. **Preserve Evidence**: Link all evidence before closing

### Status Update Frequency

**Active Incidents (Critical/High)**:
- Update every 2 hours minimum
- More frequently during active response
- Update after each significant action

**Standard Work (Medium/Low)**:
- Update at least daily
- Update when status changes
- Update before end of shift

### Comments Best Practices

**Good Comment**:
```
Investigated alert SOC-1234. Reviewed logs from affected host (WS-001).
Found suspicious PowerShell execution at 14:32 UTC:
  powershell.exe -enc [base64]
Decoded command attempts to download payload from 185.220.101.45.
Escalating to incident. Playbook: Malware Response.
Next: Isolate host, collect memory dump.
```

**Bad Comment**:
```
Looked at it. Seems bad. Doing stuff.
```

**Include**:
- What you did
- What you found
- What it means
- What you're doing next

### Transition Checklist

**Before transitioning to next state, ensure**:
- Required fields completed
- Sufficient documentation
- Evidence preserved
- Stakeholders notified (if needed)
- Next steps clear

---

## Integration with Playbooks

### Playbook Assignment

Workflows are aligned with playbook phases:

| Workflow State | Playbook Phase |
|----------------|----------------|
| Triage | Detection & Triage |
| Investigation | Investigation |
| Containment | Containment |
| Eradication | Eradication |
| Recovery | Recovery |
| Post-Incident | Post-Incident Activities |

### Auto-Linking Playbooks

Automation rules automatically link appropriate playbook based on:
- Incident Category → Specific playbook
- Detection Source → Relevant procedures
- MITRE Technique → Related guidance

---

## Metrics & Reporting

### Key Metrics by Workflow

**Alert Workflow**:
- Volume by category
- True positive rate
- False positive rate
- Mean time to triage
- Mean time to resolution
- SLA compliance

**Incident Workflow**:
- Incidents by severity
- Incidents by category
- MTTD (Mean Time to Detect)
- MTTR (Mean Time to Respond)
- MTTR (Mean Time to Resolve)
- Dwell time
- SLA compliance
- Escalation rate

**Investigation Workflow**:
- Investigations conducted
- Threats found
- Proactive vs. reactive
- IOCs discovered
- Detection rules created

### Dashboards

Standard dashboards include:
- SOC Operations Dashboard (all workflows)
- Alert Triage Dashboard (alert workflow)
- Incident Response Dashboard (incident workflow)
- Metrics Dashboard (all metrics)

See [docs/jira/DASHBOARDS.md](../jira/DASHBOARDS.md)

---

## Workflow Diagrams

### Visual Workflow Maps

Full visual diagrams available in:
- `/docs/workflows/diagrams/alert-workflow.png`
- `/docs/workflows/diagrams/incident-workflow.png`
- `/docs/workflows/diagrams/investigation-workflow.png`

---

## Workflow Maintenance

### Review Schedule

- **Weekly**: Review stuck/stale tickets
- **Monthly**: Review workflow effectiveness
- **Quarterly**: Full workflow audit
- **Annually**: Complete workflow redesign if needed

### Optimization

Track these indicators for workflow health:
- Average time in each state
- Bottlenecks (states with long durations)
- Backwards transitions (reopens)
- SLA breach patterns
- Team feedback

Make adjustments based on:
- Process improvements
- Tool changes
- Team structure changes
- Threat landscape evolution

---

## Support

Questions about workflows:
- SOC Team Lead: [contact]
- JIRA Administrator: [contact]
- Process documentation: This document

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Operations Team
