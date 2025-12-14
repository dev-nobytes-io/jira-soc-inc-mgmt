# Knowledge Base Configuration Items

## Overview

Knowledge Base articles (playbooks, runbooks, procedures, documentation) are treated as Configuration Items in the SOC case management system. This creates trackable relationships between incidents and documentation, enabling analytics on playbook effectiveness and identifying documentation gaps.

## Knowledge Base as Configuration Items

### KB Naming Convention
- **Format**: `KB-{4-digit-ID}` or Confluence URL
- **Example**: `KB-0042`, `KB-1337`
- **Alternative**: Full Confluence URLs

### KB Metadata Structure

```yaml
kb_id: KB-0042
title: "Credential Dumping Response Playbook"
type: "Playbook"
category: "Incident Response"
subcategory: "Credential Access"
confluence_url: "https://confluence.company.com/display/SOC/KB-0042"
status: "Published"
version: "2.1"
created: "2024-06-15"
last_updated: "2025-12-14"
owner: "SOC Team Lead"
reviewers: ["IR Team", "Threat Intel"]
review_frequency: "Quarterly"

# Linkages
mitre_attack:
  - T1003.001  # LSASS Memory
  - T1003.002  # SAM
  - T1558.003  # Kerberoasting

detection_analytics:
  - ANALYTIC-003
  - ANALYTIC-004
  - ANALYTIC-009

react_actions:
  - RA3101  # Disable compromised credentials
  - RA4101  # Full credential reset

use_cases:
  - UC-004  # Credential Theft

nist_csf:
  - RS.AN (Respond - Analysis)
  - RS.MI (Respond - Mitigation)

picerl_phase:
  - Containment
  - Eradication

# Usage Metrics
incident_references: 23
avg_mttr: "2.3 hours"
effectiveness_rating: 4.5
last_used: "2025-12-10"
```

## KB Classification

### By Type

#### 1. Playbooks (KB-0xxx series)
Response procedures for specific incident types

**Examples**:
- KB-0011: Phishing Response Playbook
- KB-0027: Malware Execution Response
- KB-0042: Credential Dumping Response
- KB-0045: Lateral Movement Response
- KB-0051: Data Exfiltration Response

**Structure**:
- Incident overview
- Initial response steps
- Investigation procedures
- Containment actions
- Eradication steps
- Recovery procedures
- Lessons learned template

#### 2. Runbooks (KB-1xxx series)
Operational procedures and how-to guides

**Examples**:
- KB-1001: SIEM Alert Investigation Workflow
- KB-1015: Evidence Collection Procedures
- KB-1023: PowerShell Analysis Guide
- KB-1042: Log Analysis Best Practices
- KB-1067: Threat Hunting Methodology

**Structure**:
- Purpose and scope
- Prerequisites
- Step-by-step procedures
- Expected outcomes
- Troubleshooting
- References

#### 3. Reference Documentation (KB-2xxx series)
Technical reference and knowledge articles

**Examples**:
- KB-2005: Windows Event ID Reference
- KB-2018: MITRE ATT&CK Quick Reference
- KB-2033: Common IOC Patterns
- KB-2041: Log Source Inventory
- KB-2055: Tool Documentation

**Structure**:
- Overview
- Technical details
- Use cases
- Examples
- Related articles

#### 4. Training Materials (KB-3xxx series)
Training guides and educational content

**Examples**:
- KB-3001: SOC Analyst Onboarding
- KB-3012: JIRA Workflow Training
- KB-3025: Detection Engineering Basics
- KB-3037: Threat Intelligence 101
- KB-3048: Incident Response Fundamentals

**Structure**:
- Learning objectives
- Prerequisites
- Lesson content
- Hands-on exercises
- Assessment/quiz
- Additional resources

#### 5. Post-Incident Reviews (KB-4xxx series)
Lessons learned from actual incidents

**Examples**:
- KB-4012: PIR - Ransomware Incident (2025-03)
- KB-4023: PIR - Insider Threat Case (2025-06)
- KB-4034: PIR - BEC Attack (2025-09)
- KB-4045: PIR - Supply Chain Compromise (2025-11)

**Structure**:
- Executive summary
- Incident timeline
- Root cause analysis
- Response effectiveness
- What went well
- What could improve
- Action items
- Recommendations

#### 6. Threat Intelligence Reports (KB-5xxx series)
Threat actor profiles, campaign analysis

**Examples**:
- KB-5007: APT29 Threat Profile
- KB-5018: Ransomware Trends Q4 2025
- KB-5024: Phishing Campaign Analysis
- KB-5033: Zero-Day Vulnerability Tracking
- KB-5041: Industry Threat Landscape

**Structure**:
- Executive summary
- Threat actor/campaign overview
- TTPs (MITRE ATT&CK mapping)
- IOCs
- Detection recommendations
- Mitigation strategies
- References

## JIRA Integration

### Custom Fields for KB Linking

#### 1. Knowledge Base References
- **Field Name**: Knowledge Base References
- **Type**: URL field or Multi-line text
- **Format**: KB-{ID} or full Confluence URLs
- **Usage**: Link relevant KB articles to incidents
- **Multiple**: Yes (can link multiple articles)

**Example Values**:
```
KB-0042 (Credential Dumping Response)
KB-1023 (PowerShell Analysis Guide)
https://confluence.company.com/display/SOC/KB-0042
```

#### 2. Primary Playbook
- **Field Name**: Primary Playbook
- **Type**: Single-select dropdown or URL field
- **Usage**: Main playbook used for incident response
- **Auto-populated**: Based on Incident Category

**Auto-population Mapping**:
```
Incident Category → Primary Playbook

Phishing → KB-0011 (Phishing Response)
Malware → KB-0027 (Malware Response)
Compromised Account → KB-0042 (Credential Dumping)
Lateral Movement → KB-0045 (Lateral Movement)
Data Exfiltration → KB-0051 (Data Exfiltration)
Insider Threat → KB-0061 (Insider Threat)
Ransomware → KB-0073 (Ransomware Response)
```

#### 3. KB Effectiveness Rating
- **Field Name**: Playbook Effectiveness
- **Type**: Single-select (1-5 stars)
- **Usage**: Rate playbook helpfulness
- **Required**: On incident closure
- **Purpose**: Track KB quality

### Automation Rules for KB

#### Auto-link Playbook
```
Trigger: Incident Category is set
Condition: Category is not empty
Action:
  Look up Primary Playbook for category
  Populate "Primary Playbook" field
  Add comment: "Playbook: [Link]"
```

#### Add KB Reference on Workflow Transition
```
Trigger: Workflow status changes to specific state
Action: Add relevant KB article

Mappings:
  Status = "Investigation" → Add KB-1001 (Investigation Workflow)
  Status = "Containment" → Add containment-specific KB
  Status = "Eradication" → Add eradication-specific KB
  Status = "Recovery" → Add recovery-specific KB
  Status = "Post-Incident" → Add KB-4xxx template
```

#### KB Effectiveness Tracking
```
Trigger: Incident closed
Condition: Playbook Effectiveness not rated
Action:
  Prompt user to rate playbook (1-5 stars)
  Comment: "Please rate the effectiveness of [Playbook]"
```

#### Link Related KB Articles
```
Trigger: MITRE ATT&CK Technique added
Condition: Technique has related KB articles
Action:
  Look up KB articles for technique
  Add to Knowledge Base References
  Comment: "Related: [KB articles]"

Example:
  IF Technique = "T1003.001":
    Add KB-0042 (Credential Dumping Response)
    Add KB-1023 (PowerShell Analysis)
```

## KB Analytics & Reporting

### KB Usage Metrics

#### Most Referenced KB Articles
```sql
SELECT
  kb_reference,
  COUNT(*) as incident_count,
  AVG(playbook_effectiveness) as avg_rating
FROM incidents
WHERE kb_reference IS NOT NULL
GROUP BY kb_reference
ORDER BY incident_count DESC
LIMIT 10
```

**Dashboard Widget**: Table showing top KB articles

#### KB Articles with No Usage
```sql
SELECT kb_id, title, last_updated
FROM knowledge_base
WHERE kb_id NOT IN (
  SELECT DISTINCT kb_reference
  FROM incidents
  WHERE created > NOW() - INTERVAL '6 months'
)
```

**Action**: Review for archival or promotion

#### KB Effectiveness Distribution
```
Widget: Pie chart
Segments:
  - 5 stars: 45%
  - 4 stars: 30%
  - 3 stars: 15%
  - 2 stars: 7%
  - 1 star: 3%
```

**Action**: Improve low-rated KB articles

#### MTTR by Playbook
```
Query: Average MTTR grouped by primary playbook

Example Output:
┌──────────┬───────────────────────────┬──────────┬──────────┐
│ KB ID    │ Playbook                  │ Incidents│ Avg MTTR │
├──────────┼───────────────────────────┼──────────┼──────────┤
│ KB-0011  │ Phishing Response         │ 47       │ 1.2 hrs  │
│ KB-0042  │ Credential Dumping        │ 23       │ 2.3 hrs  │
│ KB-0027  │ Malware Response          │ 19       │ 3.1 hrs  │
│ KB-0045  │ Lateral Movement          │ 12       │ 4.7 hrs  │
└──────────┴───────────────────────────┴──────────┴──────────┘
```

**Insight**: Lower MTTR = more effective playbook

### KB Coverage Analysis

#### Coverage by Incident Category
```
Query: % of incidents with linked playbook

Example Output:
Category               | Incidents | With Playbook | Coverage
-----------------------|-----------|---------------|----------
Phishing               | 47        | 47            | 100%
Malware                | 19        | 19            | 100%
Credential Theft       | 23        | 23            | 100%
Lateral Movement       | 12        | 10            | 83%
Data Exfiltration      | 8         | 6             | 75%
Insider Threat         | 5         | 2             | 40% ⚠
Policy Violation       | 15        | 8             | 53% ⚠
```

**Action**: Create playbooks for low-coverage categories

#### Coverage by MITRE ATT&CK Technique
```
Query: Techniques with/without KB articles

Example:
Total Techniques: 100
With Playbook: 67
Without Playbook: 33
Coverage: 67%
```

**Action**: Prioritize KB creation for high-risk techniques

### KB Quality Metrics

#### Freshness
```
Metric: Days since last update
Target: < 180 days for critical playbooks

Example:
KB-0011: Updated 45 days ago ✓
KB-0042: Updated 120 days ago ✓
KB-0027: Updated 380 days ago ✗ (Overdue)
```

#### Completeness
```
Checklist:
☑ Executive summary
☑ Step-by-step procedures
☑ MITRE ATT&CK mapping
☑ Detection analytics links
☑ RE&CT actions
☐ Diagrams/screenshots (optional)
☐ Example IOCs (optional)

Completeness: 71% (5/7)
```

#### Review Status
```
Review Frequency: Quarterly
Last Review: 2025-09-14
Next Review: 2025-12-14 (TODAY)
Status: DUE ⚠
```

## KB Maintenance Workflows

### Quarterly KB Review

```
1. Generate KB Usage Report
   - Usage frequency
   - Effectiveness ratings
   - Last update dates
   - Coverage gaps

2. Identify Action Items
   - Update stale KB articles (>180 days)
   - Improve low-rated articles (<3 stars)
   - Archive unused articles (0 references in 1 year)
   - Create KB for gaps

3. Assign Owners
   - Create JIRA tasks for updates
   - Assign to subject matter experts
   - Set target completion dates

4. Track Progress
   - Monitor task completion
   - Review updated articles
   - Validate improvements

5. Measure Impact
   - Re-check effectiveness ratings
   - Monitor MTTR changes
   - Update coverage metrics
```

### KB Creation Workflow

```
1. Identify Need
   Triggers:
   - New incident type without playbook
   - Recurring incident requiring guidance
   - Post-incident lesson learned
   - Gap identified in coverage analysis

2. Create JIRA Task: "KB Creation - [Title]"
   - Type: Documentation
   - Priority: Based on incident frequency/severity
   - Assigned: SME
   - Due: Based on priority

3. Draft KB Article
   - Use template for KB type
   - Include all required sections
   - Map to MITRE ATT&CK
   - Link to detection analytics
   - Add RE&CT actions

4. Peer Review
   - Technical review
   - Editorial review
   - Validation with test scenario

5. Publish
   - Publish to Confluence
   - Assign KB-{ID}
   - Update KB catalog
   - Add to JIRA automation mappings

6. Socialize
   - Announce to team
   - Add to training materials
   - Reference in related tickets
```

### KB Update Workflow

```
Triggers:
- Scheduled quarterly review
- Low effectiveness rating
- Playbook failed during incident
- Process/tool change
- Lessons learned from incident

Process:
1. Create JIRA task: "KB Update - KB-{ID}"
2. Review current content
3. Identify improvements needed
4. Update article
5. Peer review
6. Publish updated version
7. Increment version number
8. Notify team of changes
```

## Confluence Integration

### Confluence Space Structure
```
SOC Knowledge Base
├── 📁 Playbooks (KB-0xxx)
│   ├── KB-0011: Phishing Response
│   ├── KB-0027: Malware Response
│   └── ...
│
├── 📁 Runbooks (KB-1xxx)
│   ├── KB-1001: Alert Investigation
│   ├── KB-1023: PowerShell Analysis
│   └── ...
│
├── 📁 Reference (KB-2xxx)
│   ├── KB-2005: Event ID Reference
│   ├── KB-2018: ATT&CK Quick Ref
│   └── ...
│
├── 📁 Training (KB-3xxx)
│   ├── KB-3001: Analyst Onboarding
│   └── ...
│
├── 📁 Post-Incident Reviews (KB-4xxx)
│   ├── 2025 PIRs
│   └── ...
│
└── 📁 Threat Intelligence (KB-5xxx)
    ├── Threat Profiles
    └── Campaign Analysis
```

### KB Page Template (Confluence)

```markdown
# [KB-XXXX] [Title]

**Status**: Draft | In Review | Published | Archived
**Version**: X.X
**Created**: YYYY-MM-DD
**Last Updated**: YYYY-MM-DD
**Owner**: [Name/Team]
**Reviewers**: [Names]
**Next Review**: YYYY-MM-DD

---

## Quick Reference
- **Incident Type**: [Category]
- **Severity**: [Typical severity]
- **MITRE ATT&CK**: [Techniques]
- **Avg Response Time**: [Duration]
- **Detection**: [Analytics]

---

## Overview
[Brief description of incident type or procedure]

## Scope
- **Applies to**: [Systems, networks, users]
- **Not applicable to**: [Exclusions]

## Prerequisites
- Access to [tools]
- Permissions: [required]
- Knowledge of: [topics]

## Procedure

### Phase 1: [Name]
1. Step 1
   - Details
   - Commands/screenshots
   - Expected output

2. Step 2
   ...

### Phase 2: [Name]
...

## MITRE ATT&CK Mapping
- **Tactics**: [List]
- **Techniques**: [T-codes with descriptions]
- **Sub-techniques**: [Details]

## Detection Analytics
- ANALYTIC-XXX: [Description]
- ANALYTIC-YYY: [Description]

## RE&CT Actions
- RA-XXXX: [Action description]
- RA-YYYY: [Action description]

## NIST CSF Mapping
- Function.Category: [Description]

## PICERL Phase
- [Phase]: [Activities]

## Success Criteria
- [ ] [Criterion 1]
- [ ] [Criterion 2]

## Common Pitfalls
- [Pitfall and solution]

## References
- [External links]
- [Related KB articles]
- [Vendor documentation]

## Revision History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | [Name] | Initial creation |
| 1.1 | YYYY-MM-DD | [Name] | [Changes] |
```

## Next Steps

1. **Catalog Existing KB** - Document all current KB articles
2. **Implement JIRA Fields** - Add KB custom fields
3. **Configure Automation** - Auto-link KB articles
4. **Establish Metrics** - Track KB usage and effectiveness
5. **Quarterly Reviews** - Schedule regular KB maintenance

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Knowledge Management Team
