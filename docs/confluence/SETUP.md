# Confluence Setup Guide for SOC

## Overview

This guide provides step-by-step instructions for setting up Confluence as your SOC knowledge base, playbook repository, and incident documentation system.

**Estimated Setup Time**: 45-60 minutes
**Required Permissions**: Confluence Administrator

## Table of Contents

1. [Space Creation](#space-creation)
2. [Space Structure](#space-structure)
3. [Page Templates](#page-templates)
4. [Permissions](#permissions)
5. [Integration with JIRA](#integration-with-jira)
6. [Content Population](#content-population)
7. [Best Practices](#best-practices)

---

## Space Creation

### Step 1: Create SOC Space

1. Navigate to **Spaces** → **Create Space**
2. Select **Team Space** or **Knowledge Base**
3. Configure space:
   - **Name**: SOC Operations
   - **Key**: SOC
   - **Description**: Security Operations Center knowledge base, playbooks, and incident documentation
   - **Permissions**: Private (configure later)

### Step 2: Space Settings

Configure basic space settings:

**Path**: Space Settings (⚙️) → Look and Feel

```
Logo: [SOC/Security logo]
Header: Security Operations Center
Color Scheme: Professional (Blue/Gray recommended)
Sidebar: Enable for easy navigation
```

---

## Space Structure

Create the following page hierarchy in your SOC space:

```
📁 SOC Operations (Home)
│
├── 📁 Playbooks & Response Procedures
│   ├── 📄 Playbook Index
│   ├── 📁 Incident Response Playbooks
│   │   ├── 📄 Phishing Response
│   │   ├── 📄 Malware/Ransomware Response
│   │   ├── 📄 Compromised Account Response
│   │   ├── 📄 Data Exfiltration Response
│   │   ├── 📄 Insider Threat Response
│   │   └── 📄 DDoS Response
│   ├── 📁 Detection Use Cases
│   │   ├── 📄 Use Case Template
│   │   └── 📄 [Individual use cases]
│   └── 📁 Standard Operating Procedures
│       ├── 📄 Alert Triage SOP
│       ├── 📄 Evidence Collection SOP
│       ├── 📄 Escalation SOP
│       └── 📄 Communication SOP
│
├── 📁 Knowledge Base
│   ├── 📁 Threat Intelligence
│   │   ├── 📄 Active Threats
│   │   ├── 📄 Threat Actor Profiles
│   │   ├── 📄 IOC Repository
│   │   └── 📄 Campaign Tracking
│   ├── 📁 Tool Documentation
│   │   ├── 📄 SIEM User Guide
│   │   ├── 📄 EDR User Guide
│   │   ├── 📄 Forensics Tools
│   │   └── 📄 Investigation Tools
│   ├── 📁 System & Architecture
│   │   ├── 📄 Network Diagram
│   │   ├── 📄 Asset Inventory
│   │   ├── 📄 Critical Systems
│   │   └── 📄 Security Tools Inventory
│   └── 📁 Policies & Standards
│       ├── 📄 Incident Response Policy
│       ├── 📄 Classification Standards
│       └── 📄 Retention Policy
│
├── 📁 Post-Incident Reviews
│   ├── 📄 PIR Template
│   ├── 📁 2025
│   ├── 📁 2024
│   └── 📄 Lessons Learned Summary
│
├── 📁 Metrics & Reporting
│   ├── 📄 Dashboard Links
│   ├── 📁 Monthly Reports
│   │   ├── 📄 Report Template
│   │   └── 📄 [Month-Year Reports]
│   ├── 📁 Quarterly Reviews
│   └── 📄 Key Performance Indicators
│
├── 📁 Team Operations
│   ├── 📄 On-Call Schedule
│   ├── 📄 Team Roster & Contacts
│   ├── 📄 Escalation Matrix
│   ├── 📁 Training Materials
│   │   ├── 📄 New Analyst Onboarding
│   │   ├── 📄 Tool Training
│   │   └── 📄 Exercise Scenarios
│   └── 📁 Meeting Notes
│       ├── 📄 Weekly SOC Sync
│       └── 📄 Monthly Review
│
└── 📁 Reference Materials
    ├── 📄 Useful Links
    ├── 📄 External Resources
    ├── 📄 Regulatory Requirements
    └── 📄 Industry Frameworks (NIST, MITRE, etc.)
```

### Creating the Structure

1. Create each parent page manually
2. Use **+** to add child pages
3. Organize in logical hierarchy
4. Use consistent naming conventions

---

## Page Templates

### Template 1: Incident Response Playbook

**Template Name**: Incident Response Playbook

**Template Content**:

```markdown
# [Incident Type] Response Playbook

## Overview

**Incident Type**: [Phishing, Malware, etc.]
**Last Updated**: [Date]
**Owner**: [Team/Person]
**Review Frequency**: Quarterly

---

## Incident Classification

**Severity Criteria**:
- **Critical**: [Define criteria]
- **High**: [Define criteria]
- **Medium**: [Define criteria]
- **Low**: [Define criteria]

**Common Indicators**:
- [Indicator 1]
- [Indicator 2]
- [Indicator 3]

---

## Response Phases

### Phase 1: Detection & Triage (0-15 minutes)

**Objective**: Verify incident and gather initial information

**Actions**:
1. Review alert details in SIEM/EDR
2. Verify it's not a false positive
3. Identify affected assets
4. Determine severity
5. Create JIRA incident ticket

**Decision Point**:
- ✅ True Positive → Proceed to Investigation
- ❌ False Positive → Document and close

---

### Phase 2: Investigation (15 minutes - 2 hours)

**Objective**: Understand scope and impact

**Investigation Steps**:
1. [ ] Gather logs from affected systems
2. [ ] Review user activity
3. [ ] Check for lateral movement
4. [ ] Identify additional indicators
5. [ ] Document findings in JIRA

**Key Questions**:
- What happened?
- When did it happen?
- How did it happen?
- What systems are affected?
- What data is at risk?

**Tools to Use**:
- [Tool 1] - [Purpose]
- [Tool 2] - [Purpose]

---

### Phase 3: Containment (Immediate)

**Objective**: Stop the spread and prevent further damage

**Containment Actions**:
1. [ ] [Specific containment action]
2. [ ] [Specific containment action]
3. [ ] [Specific containment action]

**Short-term Containment**:
- [Action items]

**Long-term Containment**:
- [Action items]

**Communication**:
- Notify: [Stakeholders]
- Update: JIRA ticket status
- Brief: [Management if criteria met]

---

### Phase 4: Eradication

**Objective**: Remove threat from environment

**Eradication Steps**:
1. [ ] [Specific eradication action]
2. [ ] [Specific eradication action]
3. [ ] [Specific eradication action]

**Verification**:
- [ ] Scan systems for remaining indicators
- [ ] Verify removal with [tool]
- [ ] Confirm no persistence mechanisms

---

### Phase 5: Recovery

**Objective**: Restore normal operations safely

**Recovery Steps**:
1. [ ] [Recovery action]
2. [ ] [Recovery action]
3. [ ] [Recovery action]

**Monitoring**:
- Enhanced monitoring for [duration]
- Watch for indicators: [list]

---

### Phase 6: Post-Incident

**Objective**: Document and improve

**Post-Incident Tasks**:
1. [ ] Complete Post-Incident Review (PIR)
2. [ ] Update IOC repository
3. [ ] Improve detection rules
4. [ ] Update playbook if needed
5. [ ] Brief stakeholders
6. [ ] Document lessons learned

---

## Escalation Criteria

Escalate to Incident Response Team Lead if:
- [ ] Severity is Critical
- [ ] Impact spans multiple systems/locations
- [ ] Sensitive data confirmed compromised
- [ ] Advanced persistent threat suspected
- [ ] After-hours and exceeds authority

**Escalation Contact**: [Contact info]

---

## Evidence Collection

**Required Evidence**:
- [ ] System logs (Event Viewer, syslog)
- [ ] Network traffic (PCAPs)
- [ ] Email headers/samples (if applicable)
- [ ] Screenshots of indicators
- [ ] Memory dumps (if applicable)
- [ ] Disk images (if applicable)

**Evidence Handling**:
- Store in: [Evidence repository]
- Chain of custody: [Process]
- Retention: [Duration]

---

## Communication Plan

### Internal Communication

**Immediate Notification** (within 15 min):
- SOC Team Lead
- On-call Incident Responder

**Regular Updates** (every 2 hours for Critical/High):
- Security Management
- Affected business units
- IT Operations

### External Communication

**When Required**:
- Legal (if regulatory implications)
- PR/Communications (if public-facing)
- Law Enforcement (if criminal activity)
- Customers (if their data affected)

**Approval Required From**: [Title/Role]

---

## Tools & Resources

### Primary Tools
- **Detection**: [Tool name and access link]
- **Investigation**: [Tool name and access link]
- **Containment**: [Tool name and access link]
- **Documentation**: JIRA ticket

### Reference Materials
- [Related playbook]
- [Tool documentation]
- [Threat intelligence source]

---

## Metrics

Track the following for continuous improvement:
- Time to detect
- Time to respond
- Time to contain
- Time to eradicate
- Time to recover
- False positive rate
- Recurrence rate

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | [Name] | Initial creation |

---

## Appendix

### A. Command Reference

```bash
# Useful commands for this incident type
[command 1]
[command 2]
```

### B. Decision Tree

[Flowchart or decision tree for complex scenarios]

### C. Contact List

| Role | Name | Contact |
|------|------|---------|
| SOC Lead | [Name] | [Email/Phone] |
| IR Team | [Name] | [Email/Phone] |

```

**How to Create Template**:

1. Go to **Space Settings** → **Templates**
2. Click **Create Template**
3. Name: "Incident Response Playbook"
4. Paste content above
5. Save and promote

---

### Template 2: Post-Incident Review (PIR)

**Template Name**: Post-Incident Review

**Template Content**:

```markdown
# Post-Incident Review - [JIRA-XXX]

**Incident**: [Brief description]
**JIRA Ticket**: [SOC-XXX] - [Link]
**Date of Incident**: [YYYY-MM-DD]
**Date of Review**: [YYYY-MM-DD]
**Facilitator**: [Name]
**Attendees**: [Names]

---

## Executive Summary

[2-3 paragraph summary of incident, impact, and resolution]

---

## Incident Details

### Timeline

| Time | Event | Actor |
|------|-------|-------|
| YYYY-MM-DD HH:MM | Initial detection | [SIEM/EDR/User] |
| YYYY-MM-DD HH:MM | Triage began | [Analyst name] |
| YYYY-MM-DD HH:MM | Incident confirmed | [Analyst name] |
| YYYY-MM-DD HH:MM | Containment implemented | [Responder name] |
| YYYY-MM-DD HH:MM | Eradication completed | [Responder name] |
| YYYY-MM-DD HH:MM | Recovery finished | [Responder name] |
| YYYY-MM-DD HH:MM | Incident closed | [Analyst name] |

### What Happened

**Initial Detection**:
[How was the incident first detected?]

**Attack Vector**:
[How did the adversary gain access?]

**Actions Taken by Threat Actor**:
- [Action 1]
- [Action 2]

**Systems/Data Affected**:
- [System/Data 1] - [Impact level]
- [System/Data 2] - [Impact level]

---

## Response Effectiveness

### What Went Well

1. **[Success factor 1]**
   - [Details]

2. **[Success factor 2]**
   - [Details]

### What Could Be Improved

1. **[Improvement area 1]**
   - Issue: [Description]
   - Impact: [How it affected response]
   - Recommendation: [How to fix]

2. **[Improvement area 2]**
   - Issue: [Description]
   - Impact: [How it affected response]
   - Recommendation: [How to fix]

---

## Root Cause Analysis

**Primary Root Cause**:
[Detailed description of root cause]

**Contributing Factors**:
1. [Factor 1]
2. [Factor 2]

**5 Whys Analysis** (if applicable):
1. Why did X happen? [Answer]
2. Why did [Answer 1] happen? [Answer]
3. Why did [Answer 2] happen? [Answer]
4. Why did [Answer 3] happen? [Answer]
5. Why did [Answer 4] happen? [ROOT CAUSE]

---

## Metrics

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Time to Detect | [Target] | [Actual] | ✅/❌ |
| Time to Respond | [Target] | [Actual] | ✅/❌ |
| Time to Contain | [Target] | [Actual] | ✅/❌ |
| Time to Eradicate | [Target] | [Actual] | ✅/❌ |
| Time to Recover | [Target] | [Actual] | ✅/❌ |
| **Total MTTR** | [Target] | [Actual] | ✅/❌ |

---

## Action Items

| # | Action | Owner | Due Date | Status |
|---|--------|-------|----------|--------|
| 1 | [Specific action item] | [Name] | YYYY-MM-DD | 🔄 In Progress |
| 2 | [Specific action item] | [Name] | YYYY-MM-DD | ⏳ Not Started |
| 3 | [Specific action item] | [Name] | YYYY-MM-DD | ✅ Complete |

**JIRA Epic**: [Create epic to track action items]

---

## Lessons Learned

### Technical Lessons

1. **Detection**:
   - [Lesson learned about detection]

2. **Response**:
   - [Lesson learned about response]

3. **Recovery**:
   - [Lesson learned about recovery]

### Process Lessons

1. **Communication**:
   - [Lesson learned about communication]

2. **Documentation**:
   - [Lesson learned about documentation]

3. **Coordination**:
   - [Lesson learned about team coordination]

### Organizational Lessons

1. [High-level lesson for organization]
2. [High-level lesson for organization]

---

## Recommendations

### Immediate (0-30 days)

1. **[Recommendation]**
   - Priority: High
   - Effort: [Low/Medium/High]
   - Owner: [Name]

### Short-term (1-3 months)

1. **[Recommendation]**
   - Priority: Medium
   - Effort: [Low/Medium/High]
   - Owner: [Name]

### Long-term (3-12 months)

1. **[Recommendation]**
   - Priority: Low
   - Effort: [Low/Medium/High]
   - Owner: [Name]

---

## Appendix

### A. Evidence Collected

- [Evidence item 1 with link]
- [Evidence item 2 with link]

### B. External References

- [External report or reference]

### C. Related Incidents

- [Related JIRA ticket]

---

**Next Review Date**: [3 months from incident]
**PIR Status**: ✅ Complete | 🔄 In Progress | ⏳ Pending
```

**How to Create Template**:

1. Space Settings → Templates → Create Template
2. Name: "Post-Incident Review"
3. Paste content
4. Save and promote

---

### Template 3: Monthly SOC Report

**Template Name**: Monthly SOC Report

**Template Content**:

```markdown
# SOC Monthly Report - [Month] [Year]

**Reporting Period**: [Start Date] to [End Date]
**Prepared By**: [Name]
**Date**: [YYYY-MM-DD]

---

## Executive Summary

[High-level summary of the month's security posture, major incidents, and trends]

**Key Highlights**:
- [Highlight 1]
- [Highlight 2]
- [Highlight 3]

---

## Incident Statistics

### Overall Metrics

| Metric | This Month | Last Month | Change |
|--------|------------|------------|--------|
| Total Alerts | [#] | [#] | [↑/↓ X%] |
| True Positives | [#] | [#] | [↑/↓ X%] |
| False Positives | [#] | [#] | [↑/↓ X%] |
| Incidents Created | [#] | [#] | [↑/↓ X%] |
| Incidents Closed | [#] | [#] | [↑/↓ X%] |
| Mean Time to Detect (MTTD) | [X hours] | [X hours] | [↑/↓ X%] |
| Mean Time to Respond (MTTR) | [X hours] | [X hours] | [↑/↓ X%] |
| True Positive Rate | [X%] | [X%] | [↑/↓ X%] |

### Incidents by Severity

[Pie chart or table]

| Severity | Count | % of Total |
|----------|-------|------------|
| Critical | [#] | [X%] |
| High | [#] | [X%] |
| Medium | [#] | [X%] |
| Low | [#] | [X%] |

### Incidents by Category

| Category | Count | % of Total |
|----------|-------|------------|
| Phishing | [#] | [X%] |
| Malware | [#] | [X%] |
| Compromised Account | [#] | [X%] |
| Data Exfiltration | [#] | [X%] |
| Other | [#] | [X%] |

---

## Major Incidents

### Critical/High Severity Incidents

#### [SOC-XXX] - [Incident Title]
- **Severity**: Critical
- **Category**: [Category]
- **Date**: [YYYY-MM-DD]
- **Status**: Closed
- **Summary**: [Brief summary]
- **Impact**: [Impact description]
- **Resolution**: [How it was resolved]
- **PIR**: [Link to PIR]

---

## Threat Landscape

### Observed Threats

1. **[Threat/Campaign Name]**
   - Description: [Details]
   - Indicators: [IOCs]
   - Mitigation: [Actions taken]

2. **[Threat/Campaign Name]**
   - Description: [Details]
   - Indicators: [IOCs]
   - Mitigation: [Actions taken]

### Emerging Threats

- [Threat 1]: [Brief description and our preparedness]
- [Threat 2]: [Brief description and our preparedness]

---

## Detection & Response

### Top Alert Sources

| Source | Alerts Generated | True Positives | False Positives |
|--------|------------------|----------------|-----------------|
| SIEM | [#] | [#] | [#] |
| EDR | [#] | [#] | [#] |
| Email Gateway | [#] | [#] | [#] |
| Firewall/IDS | [#] | [#] | [#] |

### Detection Improvements

- [Improvement 1]
- [Improvement 2]

### Tuning Activities

- [Tuning activity 1]
- [Tuning activity 2]

---

## SLA Performance

| SLA Metric | Target | Actual | Compliance |
|------------|--------|--------|------------|
| Critical - Time to Response | 30 min | [X min] | [X%] |
| Critical - Time to Resolution | 4 hours | [X hours] | [X%] |
| High - Time to Response | 2 hours | [X hours] | [X%] |
| High - Time to Resolution | 24 hours | [X hours] | [X%] |

**SLA Compliance**: [Overall %]

**SLA Breaches**: [#]
- [Brief description of any breaches]

---

## Team Performance

### Workload Distribution

| Team Member | Tickets Worked | Avg Resolution Time |
|-------------|----------------|---------------------|
| [Name 1] | [#] | [X hours] |
| [Name 2] | [#] | [X hours] |
| [Name 3] | [#] | [X hours] |

### Training & Development

- [Training completed]
- [Certifications obtained]
- [Exercises conducted]

---

## Operational Improvements

### Completed This Month

1. **[Improvement]**
   - Impact: [Description]

2. **[Improvement]**
   - Impact: [Description]

### Planned for Next Month

1. [Planned improvement]
2. [Planned improvement]

---

## Challenges & Risks

### Current Challenges

1. **[Challenge]**
   - Impact: [Description]
   - Mitigation: [Plan]

### Identified Risks

1. **[Risk]**
   - Likelihood: [High/Medium/Low]
   - Impact: [High/Medium/Low]
   - Mitigation: [Plan]

---

## Recommendations

### Management Actions Needed

1. **[Recommendation]**
   - Justification: [Why needed]
   - Benefit: [Expected outcome]

### Resource Requests

- [Resource request with justification]

---

## Appendix

### A. Detailed Incident List

[Link to JIRA filter or exported list]

### B. JIRA Dashboard

[Embed or link to SOC dashboard]

### C. Trend Charts

[Include relevant charts]

---

**Next Report Due**: [Date]
```

---

## Permissions

### Permission Scheme

**Path**: Space Settings → Permissions

Configure permissions for different user groups:

#### SOC Team (Full Access)
- ✅ View pages
- ✅ Add pages
- ✅ Edit pages
- ✅ Delete pages
- ✅ Add comments
- ✅ Delete comments (own)
- ✅ Add attachments
- ✅ Export pages

#### Security Team (Contribute)
- ✅ View pages
- ✅ Add pages (in designated areas)
- ✅ Edit pages (own)
- ✅ Add comments
- ✅ Add attachments

#### Management (Read + Comment)
- ✅ View pages
- ✅ Add comments
- ❌ Edit pages

#### Company-Wide (Read-Only - for specific pages)
- ✅ View specific pages (e.g., contact lists, general SOPs)
- ❌ Edit anything

**Recommended Setup**:
- Make playbooks read-only for non-SOC
- Allow all security staff to comment
- Restrict editing of official documents
- Use page restrictions for sensitive content

---

## Integration with JIRA

### Linking Strategies

1. **Macro: JIRA Issues**
   - Embed JIRA filters in Confluence pages
   - Show current incident status on homepage

2. **Smart Links**
   - Link playbooks to JIRA issue types
   - Reference PIRs from closed incidents

3. **Automation**
   - Auto-create PIR pages from JIRA
   - Auto-link evidence to incidents

### Example Integrations

**Homepage JIRA Widget**:
```
Insert → JIRA Issues Macro
Filter: project = SOC AND status != Closed
Display: Table view with key fields
```

**Playbook JIRA Link**:
```
When creating incident of type "Phishing":
Automatically link to: [Phishing Response Playbook]
```

---

## Content Population

### Week 1: Core Structure
- [ ] Create all parent pages
- [ ] Set up templates
- [ ] Configure permissions
- [ ] Create home page with navigation

### Week 2: Critical Content
- [ ] Populate 5 main playbooks
- [ ] Create SOPs for triage and escalation
- [ ] Add contact lists and escalation matrix
- [ ] Document critical tools

### Week 3: Knowledge Base
- [ ] Add system architecture docs
- [ ] Create asset inventory
- [ ] Document policies and standards
- [ ] Set up threat intelligence pages

### Week 4: Finalization
- [ ] Review all content
- [ ] Train team on usage
- [ ] Gather feedback
- [ ] Optimize navigation

---

## Best Practices

### Content Management

1. **Consistent Formatting**: Use templates for all similar pages
2. **Clear Navigation**: Keep structure logical and shallow
3. **Regular Updates**: Review and update quarterly
4. **Version Control**: Use page versions for tracking changes
5. **Labels**: Tag pages for easy searching
6. **Archiving**: Move old content to archive space

### Collaboration

1. **Page Owners**: Assign owner to each page
2. **Review Cycle**: Schedule regular reviews
3. **Comments**: Encourage team to comment and suggest improvements
4. **Notifications**: Watch important pages
5. **Inline Comments**: Use for specific feedback

### Search & Discovery

1. **Descriptive Titles**: Make pages easy to find
2. **Excerpts**: Add page excerpts for search results
3. **Labels**: Use consistent labeling scheme
4. **Links**: Link related pages together
5. **Table of Contents**: Add TOC to long pages

---

## Next Steps

After Confluence setup:

1. [Integrate with JIRA](../../integrations/JIRA-CONFLUENCE.md)
2. [Populate Playbooks](../../playbooks/README.md)
3. [Train Team](../processes/TRAINING.md)
4. [Establish Review Cadence](../processes/MAINTENANCE.md)

---

**Setup Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Team Lead
