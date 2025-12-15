# PICERL Incident Management Framework

## Overview

PICERL is a comprehensive incident management framework that extends the traditional NIST incident response lifecycle with emphasis on Preparation and Lessons Learned. The framework provides structure for managing security incidents from preparation through post-incident activities.

**PICERL Phases**:
- **P**reparation
- **I**dentification
- **C**ontainment
- **E**radication
- **R**ecovery
- **L**essons Learned

## Framework Structure

### Phase 1: PREPARATION (P)

**Objective**: Establish capabilities, processes, and resources needed for effective incident response.

#### P.1 - Team Preparation
- [ ] Incident response team established
- [ ] Roles and responsibilities defined
- [ ] On-call rotation configured
- [ ] Escalation paths documented
- [ ] Contact lists maintained

**JIRA Implementation**:
- Assigned Team field
- Permission schemes
- Notification schemes
- On-call schedule integration

#### P.2 - Tool Preparation
- [ ] SIEM configured and operational
- [ ] EDR/XDR deployed
- [ ] Forensic tools available
- [ ] Backup and recovery systems tested
- [ ] Communication platforms configured

**JIRA Implementation**:
- Integration with SIEM (webhook)
- Tool inventory (Configuration Items)
- Tool availability tracking

#### P.3 - Process Preparation
- [ ] Incident response playbooks documented
- [ ] Workflows configured
- [ ] SLAs defined
- [ ] Escalation criteria established
- [ ] Communication templates created

**JIRA Implementation**:
- Playbooks linked (Knowledge Base CI)
- Workflow states configured
- SLA tracking enabled
- Automation rules deployed

#### P.4 - Detection Preparation
- [ ] Detection analytics deployed
- [ ] Baselines established
- [ ] Alert routing configured
- [ ] Tuning completed
- [ ] Coverage validated

**JIRA Implementation**:
- Detection Analytics CI
- DeTT&CT coverage tracking
- False positive baseline

#### P.5 - Information Preparation
- [ ] Asset inventory current
- [ ] Network diagrams updated
- [ ] Critical systems identified
- [ ] Data classification completed
- [ ] Threat intelligence feeds active

**JIRA Implementation**:
- Affected Assets field
- Asset criticality tier
- CMDB integration

**Preparation Metrics**:
- Team readiness score
- Tool availability percentage
- Playbook coverage (% incident types)
- Detection coverage (MITRE ATT&CK %)
- Asset inventory completeness

---

### Phase 2: IDENTIFICATION (I)

**Objective**: Detect, analyze, and confirm security incidents.

#### I.1 - Event Detection
- [ ] Alert received from detection source
- [ ] Alert enriched with context
- [ ] Initial severity assigned
- [ ] Assigned to analyst

**JIRA Workflow**: New → Triage

**JIRA Fields**:
- Detection Source
- Incident Severity (initial)
- Detection Analytics CI
- IOCs

#### I.2 - Alert Triage
- [ ] Alert reviewed by analyst
- [ ] False positive assessment
- [ ] True positive confirmation
- [ ] Scope identified

**JIRA Workflow**: Triage

**Activities**:
- Review alert details
- Check for similar alerts
- Validate indicators
- Assess legitimacy

#### I.3 - Incident Declaration
- [ ] Incident criteria met
- [ ] Incident declared
- [ ] Initial notification sent
- [ ] Investigation initiated

**JIRA Workflow**: Triage → Investigation

**Triggers**:
- True positive confirmed
- Impact threshold met
- Escalation criteria satisfied

#### I.4 - Scoping & Analysis
- [ ] Affected systems identified
- [ ] Timeline established
- [ ] Attack vector determined
- [ ] Threat actor profiled (if applicable)

**JIRA Workflow**: Investigation

**JIRA Fields**:
- Affected Assets
- MITRE ATT&CK Tactics/Techniques
- Evidence Links
- Incident Category

#### I.5 - Impact Assessment
- [ ] Business impact assessed
- [ ] Data exposure evaluated
- [ ] Severity confirmed/updated
- [ ] Stakeholders identified

**JIRA Fields**:
- Incident Severity (confirmed)
- Communication Status
- Root Cause (preliminary)

**Identification Metrics**:
- Time to detect (MTTD)
- Time to triage (alert creation → triage complete)
- True positive rate
- False positive rate
- % incidents with complete scoping

---

### Phase 3: CONTAINMENT (C)

**Objective**: Limit the scope and impact of the incident.

#### C.1 - Short-term Containment
- [ ] Immediate threat stopped
- [ ] Attack progression halted
- [ ] Critical systems isolated (if needed)

**JIRA Workflow**: Investigation → Containment

**RE&CT Actions**:
- RA3101: Disable compromised credentials
- RA3201: Terminate suspicious processes
- RA3301: Block malicious IP/domain

#### C.2 - System Isolation
- [ ] Affected systems identified for isolation
- [ ] Isolation method determined
- [ ] Systems isolated from network
- [ ] Isolation verified

**Isolation Methods**:
- Network segmentation
- Firewall rules
- Physical disconnect
- VLAN isolation

#### C.3 - Evidence Preservation
- [ ] Evidence identified
- [ ] Evidence collected
- [ ] Chain of custody established
- [ ] Evidence secured

**JIRA Fields**:
- Evidence Links
- Forensic artifacts
- Collection timestamp
- Custodian

#### C.4 - Long-term Containment
- [ ] Sustainable containment strategy implemented
- [ ] Business operations maintained
- [ ] Monitoring enhanced
- [ ] Workarounds deployed (if needed)

**Considerations**:
- Business continuity
- Legal/regulatory requirements
- Forensic preservation
- Operational impact

**Containment Metrics**:
- Time to contain (TTC)
- % incidents contained within SLA
- Containment effectiveness (re-infection rate)
- Business disruption duration

---

### Phase 4: ERADICATION (E)

**Objective**: Eliminate the threat and root causes from the environment.

#### E.1 - Threat Removal
- [ ] Malware removed
- [ ] Persistence mechanisms eliminated
- [ ] Backdoors closed
- [ ] Unauthorized access removed

**JIRA Workflow**: Containment → Eradication

**RE&CT Actions**:
- RA4101: Reset compromised credentials (full scope)
- RA4201: Remove malware/persistence
- RA4401: Patch exploitation vector

#### E.2 - Vulnerability Remediation
- [ ] Root cause identified
- [ ] Vulnerability patched
- [ ] Misconfiguration corrected
- [ ] Security gap closed

**JIRA Fields**:
- Root Cause
- CVE (if applicable)
- Remediation actions

#### E.3 - Credential Reset
- [ ] Compromised credentials identified
- [ ] Passwords reset
- [ ] Sessions terminated
- [ ] MFA enforced (if applicable)

**Scope**:
- Directly compromised accounts
- Potentially exposed accounts
- Service accounts
- Administrative accounts

#### E.4 - System Hardening
- [ ] Security baseline applied
- [ ] Configurations hardened
- [ ] Unnecessary services disabled
- [ ] Logging enhanced

**Hardening Activities**:
- Apply security patches
- Update configurations
- Remove unnecessary software
- Implement least privilege

#### E.5 - Verification
- [ ] Threat eradicated confirmed
- [ ] No persistence detected
- [ ] Systems clean
- [ ] Monitoring confirms eradication

**Verification Methods**:
- Malware scans
- Vulnerability scans
- Configuration audits
- Behavioral analysis

**Eradication Metrics**:
- Time to eradicate (TTE)
- % eradication verified
- Re-infection rate
- Thoroughness score

---

### Phase 5: RECOVERY (R)

**Objective**: Restore systems and services to normal operations.

#### R.1 - System Restoration
- [ ] Restoration method determined
- [ ] Backup validation completed
- [ ] Systems restored
- [ ] Functionality verified

**JIRA Workflow**: Eradication → Recovery

**RE&CT Actions**:
- RA5001: Restore system from backup
- RA5101: Restore user access

**Restoration Methods**:
- Restore from clean backup
- Rebuild from baseline
- Patch and verify
- Reimaging

#### R.2 - Access Restoration
- [ ] User access restored
- [ ] Permissions validated
- [ ] Credentials distributed
- [ ] User communication completed

**Access Restoration**:
- Generate temporary passwords
- Deliver via secure channel
- Force password change on logon
- Restore group memberships

#### R.3 - Monitoring Enhancement
- [ ] Enhanced monitoring deployed
- [ ] Watch list created
- [ ] Alerts configured
- [ ] Baseline re-established

**Enhanced Monitoring**:
- Affected user activity
- Restored system behavior
- Similar attack patterns
- Indicators of reinfection

#### R.4 - Gradual Return to Normal
- [ ] Systems returned to production
- [ ] Services restored
- [ ] Performance validated
- [ ] Stakeholders notified

**Phased Recovery**:
1. Isolated testing environment
2. Limited production (pilot)
3. Full production
4. Normal operations

#### R.5 - Recovery Validation
- [ ] All systems operational
- [ ] No anomalies detected
- [ ] Business operations normal
- [ ] Users productive

**Validation Criteria**:
- System uptime
- Service availability
- Performance metrics
- User feedback

**Recovery Metrics**:
- Time to recover (TTR)
- Mean time to recover (MTTR)
- % systems fully recovered
- Business impact duration
- Customer impact

---

### Phase 6: LESSONS LEARNED (L)

**Objective**: Document learnings and improve security posture.

#### L.1 - Incident Documentation
- [ ] Incident timeline documented
- [ ] Root cause analysis completed
- [ ] Impact assessment documented
- [ ] Response actions recorded

**JIRA Workflow**: Recovery → Post-Incident

**RE&CT Actions**:
- RA6001: Incident documentation
- RA6002: Detection improvement
- RA6003: Control & process improvement

**Documentation Requirements**:
- Executive summary
- Detailed timeline
- Root cause analysis
- Response effectiveness
- Recommendations

#### L.2 - Post-Incident Review Meeting
- [ ] PIR meeting scheduled
- [ ] Stakeholders invited
- [ ] Review conducted
- [ ] Action items captured

**Attendees**:
- Incident response team
- IT/Security management
- Business stakeholders
- Legal/Compliance (if applicable)

**Agenda**:
1. Incident overview
2. Timeline review
3. Response effectiveness
4. What went well
5. What could be improved
6. Action items

#### L.3 - Detection Improvement
- [ ] Detection gaps identified
- [ ] New analytics designed
- [ ] Detection deployed
- [ ] Coverage validated

**Detection Improvement Activities**:
- Create new detection rules
- Tune existing rules
- Update baselines
- Enhance correlation
- Deploy to production

#### L.4 - Control Improvement
- [ ] Control gaps identified
- [ ] Remediation plan created
- [ ] Controls implemented
- [ ] Effectiveness validated

**Control Types**:
- **Preventive**: Stop attacks before they succeed
- **Detective**: Detect attacks faster
- **Responsive**: Respond more effectively
- **Corrective**: Fix root causes

#### L.5 - Process Improvement
- [ ] Process gaps identified
- [ ] Playbooks updated
- [ ] Workflows optimized
- [ ] Training delivered

**Process Updates**:
- Update response playbooks
- Refine workflows
- Update runbooks
- Improve automation
- Enhance communication

#### L.6 - Knowledge Sharing
- [ ] Lessons learned documented in KB
- [ ] Team training conducted
- [ ] Stakeholder communication completed
- [ ] Industry sharing (if appropriate)

**Knowledge Sharing**:
- Update Confluence KB
- Team training session
- Management briefing
- Industry sharing (ISAC, etc.)

**Lessons Learned Metrics**:
- % incidents with PIR completed
- Avg time to PIR completion
- # improvements identified per incident
- % improvements implemented
- Detection coverage increase

---

## PICERL Integration with JIRA

### Workflow Mapping

| JIRA Workflow State | PICERL Phase | Duration Tracking |
|---------------------|--------------|-------------------|
| (Pre-creation) | **Preparation** | Continuous |
| New | **Identification** | Alert created → Triage started |
| Triage | **Identification** | Triage duration |
| Investigation | **Identification** | Investigation duration |
| Containment | **Containment** | Time to contain (TTC) |
| Eradication | **Eradication** | Time to eradicate (TTE) |
| Recovery | **Recovery** | Time to recover (TTR) |
| Post-Incident | **Lessons Learned** | PIR duration |
| Closed | **Lessons Learned** | Total incident duration |

### Custom Fields for PICERL

#### 1. PICERL Phase
- **Type**: Single-select dropdown
- **Options**: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
- **Auto-populated**: Based on workflow state
- **Usage**: Track current phase

#### 2. PICERL Phase Timestamps
- **Fields**:
  - Identification Start
  - Containment Start
  - Eradication Start
  - Recovery Start
  - Lessons Learned Start
- **Type**: Date/Time
- **Auto-populated**: On workflow transition
- **Usage**: Calculate phase durations

#### 3. PICERL Phase Duration
- **Calculated Fields**:
  - Identification Duration
  - Containment Duration
  - Eradication Duration
  - Recovery Duration
  - Total Incident Duration
- **Type**: Number (hours)
- **Formula**: End time - Start time
- **Usage**: Performance metrics

#### 4. PICERL Checklist Completion
- **Fields**:
  - Preparation Checklist (%)
  - Identification Checklist (%)
  - Containment Checklist (%)
  - Eradication Checklist (%)
  - Recovery Checklist (%)
  - Lessons Learned Checklist (%)
- **Type**: Number (0-100)
- **Usage**: Track phase completion

### Automation Rules for PICERL

#### Auto-populate PICERL Phase
```
Trigger: Workflow status changed
Condition: Status in (New, Triage, Investigation, Containment, Eradication, Recovery, Post-Incident)
Action:
  IF Status = "New" OR "Triage" OR "Investigation":
    Set PICERL Phase = "Identification"
  IF Status = "Containment":
    Set PICERL Phase = "Containment"
    Set Containment Start = NOW()
  IF Status = "Eradication":
    Set PICERL Phase = "Eradication"
    Set Eradication Start = NOW()
  IF Status = "Recovery":
    Set PICERL Phase = "Recovery"
    Set Recovery Start = NOW()
  IF Status = "Post-Incident":
    Set PICERL Phase = "Lessons Learned"
    Set Lessons Learned Start = NOW()
```

#### Create Phase Checklists
```
Trigger: PICERL Phase changed
Action: Create sub-task with phase-specific checklist

Example - Containment Phase:
  Create sub-task: "Containment Activities"
  Checklist:
    ☐ C.1 - Short-term containment
    ☐ C.2 - System isolation
    ☐ C.3 - Evidence preservation
    ☐ C.4 - Long-term containment
```

#### SLA by PICERL Phase
```
Trigger: PICERL Phase changed
Action: Set SLA based on phase and severity

Example:
  IF Severity = "Critical" AND Phase = "Containment":
    SLA = 1 hour
  IF Severity = "High" AND Phase = "Containment":
    SLA = 4 hours
```

#### PIR Reminder
```
Trigger: Status = "Recovery"
Condition: Severity in (Critical, High)
Action:
  Wait 24 hours
  Create sub-task: "Schedule Post-Incident Review"
  Assign to: Incident Manager
  Due date: 7 days from now
```

## PICERL Metrics & KPIs

### Phase Duration Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Time to Identify (TTI)** | Alert created → Investigation started | < 15 min (Critical) |
| **Time to Contain (TTC)** | Investigation → Containment complete | < 1 hour (Critical) |
| **Time to Eradicate (TTE)** | Containment → Eradication complete | < 4 hours (Critical) |
| **Time to Recover (TTR)** | Eradication → Recovery complete | < 8 hours (Critical) |
| **Time to PIR (TTP)** | Recovery → Lessons Learned complete | < 7 days |
| **Mean Time to Respond (MTTR)** | Alert → Containment complete | < 2 hours (Critical) |
| **Total Incident Duration** | Alert → Closed | < 24 hours (Critical) |

### Phase Completion Metrics

| Metric | Description | Target |
|--------|-------------|--------|
| **Preparation Readiness** | % preparation checklist complete | > 90% |
| **Identification Accuracy** | True positive rate | > 85% |
| **Containment Effectiveness** | % incidents contained without spread | > 95% |
| **Eradication Success** | % incidents without re-infection | > 98% |
| **Recovery Completeness** | % systems fully recovered | 100% |
| **PIR Completion Rate** | % incidents with PIR completed | 100% (Critical/High) |

### Dashboards

#### PICERL Phase Distribution
```
Widget: Pie chart
Data: Count of incidents by current PICERL phase
Purpose: Identify bottlenecks
```

#### PICERL Phase Duration Trends
```
Widget: Line chart
Data: Avg duration per phase over time
Purpose: Track improvement
```

#### PICERL Maturity Scorecard
```
Widget: Scorecard
Metrics:
  - Preparation Readiness: 92%
  - Identification Accuracy: 87%
  - Containment Effectiveness: 96%
  - Eradication Success: 99%
  - Recovery Completeness: 100%
  - PIR Completion: 78%
  - Overall Maturity: 92%
```

## PICERL to NIST CSF 2.0 Mapping

| PICERL Phase | NIST CSF Function | NIST CSF Categories |
|--------------|-------------------|---------------------|
| **Preparation** | Govern (GV), Identify (ID), Protect (PR) | GV.RM, ID.AM, PR.AA, PR.DS |
| **Identification** | Detect (DE), Respond (RS) | DE.AE, DE.CM, RS.MA, RS.AN |
| **Containment** | Respond (RS) | RS.MI-01, RS.CO |
| **Eradication** | Respond (RS) | RS.MI-02, RS.AN |
| **Recovery** | Recover (RC) | RC.RP, RC.CO |
| **Lessons Learned** | Recover (RC), Govern (GV) | RC.IM, GV.RM, GV.OV |

## PICERL to RE&CT Mapping

| PICERL Phase | RE&CT Phase | RE&CT Actions |
|--------------|-------------|---------------|
| **Preparation** | N/A (Pre-incident) | Detection preparation, Tool readiness |
| **Identification** | RA1xxx (Identification) | RA1001, RA1002, RA1003 |
| **Containment** | RA3xxx (Containment) | RA3101, RA3201, RA3301 |
| **Eradication** | RA4xxx (Eradication) | RA4101, RA4201, RA4401 |
| **Recovery** | RA5xxx (Recovery) | RA5001, RA5101 |
| **Lessons Learned** | RA6xxx (Lessons Learned) | RA6001, RA6002, RA6003 |

## Implementation Guide

### Step 1: Configure JIRA Fields
- Create PICERL Phase field
- Create timestamp fields
- Create duration calculation fields
- Create checklist completion fields

### Step 2: Map Workflows
- Update workflow states
- Add PICERL transitions
- Configure transition screens
- Add validation rules

### Step 3: Deploy Automation
- Phase auto-population rules
- Timestamp capture rules
- Checklist creation rules
- SLA rules
- Notification rules

### Step 4: Create Dashboards
- Phase distribution dashboard
- Duration trends dashboard
- Maturity scorecard
- Performance metrics

### Step 5: Train Team
- PICERL framework overview
- Phase objectives and activities
- JIRA field usage
- Metrics interpretation

### Step 6: Monitor & Optimize
- Track metrics
- Identify bottlenecks
- Optimize processes
- Continuous improvement

## Benefits of PICERL Framework

### For Analysts
- Clear phase objectives
- Structured approach
- Checklist-driven activities
- Reduced decision fatigue

### For Management
- Visibility into incident phases
- Performance metrics
- Bottleneck identification
- Maturity assessment

### For Organization
- Consistent incident handling
- Improved response times
- Better preparation
- Continuous improvement culture

## References

- NIST SP 800-61r2: Computer Security Incident Handling Guide
- SANS Incident Response Process
- PICERL Framework Documentation
- RE&CT Framework
- NIST CSF 2.0

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Framework**: PICERL Incident Management
**Maintained By**: SOC Engineering Team
