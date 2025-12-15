# Security Configuration Items (CI)

## Overview

Configuration Items in SOC case management provide a structured way to link security assets, detection rules, analytics, frameworks, and knowledge base articles to incidents and cases. Similar to ServiceNow's CMDB, this creates relationships and dependencies that enable better analytics, reporting, and incident management.

## Configuration Item Types

### 1. Detection Analytics (CI Class: Detection)
- Detection rules and queries
- SIEM correlation rules
- Custom analytics
- Threat hunting queries
- Anomaly detection baselines

### 2. MITRE ATT&CK TTPs (CI Class: Threat Intelligence)
- Tactics mapping
- Techniques mapping (T-codes)
- Sub-techniques
- Procedures
- Adversary groups

### 3. RE&CT Response Actions (CI Class: Response Framework)
- Response procedures (RA-codes)
- Containment actions
- Eradication procedures
- Recovery workflows
- Lessons learned templates

### 4. DeTT&CT Detection Coverage (CI Class: Coverage Mapping)
- Detection coverage matrices
- Capability assessments
- Gap analysis results
- Coverage heatmaps

### 5. Knowledge Base Articles (CI Class: Documentation)
- Confluence pages
- Playbooks
- Runbooks
- Procedures
- Post-incident reviews
- Training materials

### 6. NIST CSF 2.0 Controls (CI Class: Framework)
- Identify functions
- Protect functions
- Detect functions
- Respond functions
- Recover functions
- Govern functions

### 7. PICERL Phases (CI Class: Incident Management)
- Preparation activities
- Identification procedures
- Containment actions
- Eradication procedures
- Recovery workflows
- Lessons Learned documentation

## CI Relationships

### Parent-Child Relationships
```
Detection Analytics (Parent)
└── MITRE ATT&CK Technique (Child)
    └── Use Cases (Child)
        └── Response Actions (Child)
            └── Knowledge Base Articles (Child)
```

### Example Relationship Chain
```
CI-0001: Credential Dumping Detection
├── Links to: T1003 (OS Credential Dumping)
├── Links to: T1003.001 (LSASS Memory)
├── Triggers: UC-004 (Credential Access Alert)
├── Invokes: RA3101 (Disable Compromised Credentials)
├── References: KB-0042 (Credential Dumping Response Playbook)
├── Maps to: NIST CSF DE.CM-7 (Detect anomalous activity)
├── Maps to: PICERL-Identification
└── Tracked in: DeTT&CT Coverage Matrix
```

## JIRA Integration

### Custom Fields for CI Linking

#### Detection Analytics CI
- **Field Name**: Detection Analytics
- **Type**: Multi-select (or Labels)
- **Format**: `ANALYTIC-{ID}` (e.g., ANALYTIC-001)
- **Usage**: Links incident to detection rules that identified it

#### MITRE ATT&CK Tactics CI
- **Field Name**: MITRE ATT&CK Tactics
- **Type**: Multi-select dropdown
- **Values**: Initial Access, Execution, Persistence, etc.
- **Usage**: Maps incident to adversary tactics

#### MITRE ATT&CK Techniques CI
- **Field Name**: MITRE ATT&CK Techniques
- **Type**: Multi-line text or Labels
- **Format**: `T{ID}` (e.g., T1003.001)
- **Usage**: Maps incident to specific techniques

#### RE&CT Response Actions CI
- **Field Name**: RE&CT Actions
- **Type**: Multi-select or Labels
- **Format**: `RA{ID}` (e.g., RA3101)
- **Usage**: Tracks response actions taken

#### Knowledge Base References CI
- **Field Name**: Knowledge Base Links
- **Type**: URL or Multi-line text
- **Format**: Confluence page URLs or `KB-{ID}`
- **Usage**: Links to relevant documentation

#### NIST CSF 2.0 Functions CI
- **Field Name**: NIST CSF Functions
- **Type**: Multi-select dropdown
- **Values**: Govern, Identify, Protect, Detect, Respond, Recover
- **Usage**: Maps incident handling to CSF functions

#### NIST CSF 2.0 Categories CI
- **Field Name**: NIST CSF Categories
- **Type**: Multi-line text or Labels
- **Format**: `{Function}.{Category}` (e.g., DE.CM-7)
- **Usage**: Specific CSF category mapping

#### PICERL Phase CI
- **Field Name**: PICERL Phase
- **Type**: Single-select dropdown
- **Values**: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
- **Usage**: Tracks current incident management phase

#### DeTT&CT Coverage ID CI
- **Field Name**: DeTT&CT Coverage
- **Type**: Labels
- **Format**: `DETTCT-{ID}`
- **Usage**: Links to detection coverage assessments

## CI Automation

### Automatic CI Linking Rules

#### Rule 1: Auto-link Detection Analytics
```
When: Issue created via SIEM webhook
Then:
  - Parse alert name/ID
  - Look up matching ANALYTIC-{ID}
  - Auto-populate "Detection Analytics" field
  - Auto-populate related MITRE ATT&CK techniques
```

#### Rule 2: Auto-link Knowledge Base
```
When: Incident Category is set
Then:
  - Look up playbook for category
  - Auto-add KB link to "Knowledge Base References"
  - Add comment with link to playbook
```

#### Rule 3: Auto-link RE&CT Actions
```
When: Workflow transitions to "Containment"
Then:
  - Auto-populate RE&CT Actions with RA3xxx codes
  - Create sub-tasks from RE&CT templates
  - Link sub-tasks to parent incident
```

#### Rule 4: Auto-update PICERL Phase
```
When: Workflow status changes
Then:
  Workflow Status → PICERL Phase mapping:
  - Triage → Identification
  - Investigation → Identification
  - Containment → Containment
  - Eradication → Eradication
  - Recovery → Recovery
  - Post-Incident → Lessons Learned
```

#### Rule 5: Auto-populate NIST CSF
```
When: PICERL Phase is set
Then:
  PICERL → NIST CSF mapping:
  - Identification → DE (Detect)
  - Containment → RS.RP (Respond - Response Planning)
  - Eradication → RS.MI (Respond - Mitigation)
  - Recovery → RC (Recover)
  - Lessons Learned → GV.RM (Govern - Risk Management)
```

## Analytics & Reporting

### CI-Based Dashboards

#### Detection Coverage Dashboard
```
Metrics:
- Total Detection Analytics (ANALYTIC-{ID} count)
- MITRE ATT&CK Coverage (% of techniques with detection)
- DeTT&CT Coverage Score
- Detection efficacy (True Positive rate per analytic)
```

#### Incident Response Maturity Dashboard
```
Metrics:
- RE&CT action completion rate
- PICERL phase duration (avg time per phase)
- NIST CSF function coverage
- Knowledge base usage (KB article references per incident)
```

#### Knowledge Base Effectiveness Dashboard
```
Metrics:
- Most referenced KB articles
- KB articles with no references (unused)
- Playbook effectiveness (MTTR by playbook)
- Documentation gaps (incidents without KB links)
```

### CI Relationship Reports

#### Report 1: Detection to Response Chain
```
Query: Show complete chain from detection → response → knowledge base

Example Output:
ANALYTIC-003 (Suspicious PowerShell Execution)
├── Detected Incidents: 47
├── MITRE ATT&CK: T1059.001 (PowerShell)
├── Avg Response Actions: RA3201, RA4201
├── Primary Playbook: KB-0038
└── MTTR: 2.3 hours
```

#### Report 2: MITRE ATT&CK Coverage
```
Query: Show detection coverage per technique

Example Output:
Tactic: Credential Access
├── T1003 (OS Credential Dumping)
│   ├── Detection: ANALYTIC-004 ✓
│   ├── Playbook: KB-0042 ✓
│   ├── RE&CT: RA3101 ✓
│   └── Coverage Score: 100%
├── T1110 (Brute Force)
│   ├── Detection: ANALYTIC-009 ✓
│   ├── Playbook: None ✗
│   ├── RE&CT: RA3301 ✓
│   └── Coverage Score: 67%
```

#### Report 3: Framework Compliance
```
Query: Show NIST CSF 2.0 coverage by incidents

Example Output:
NIST CSF Function: Detect (DE)
├── DE.AE (Anomalies and Events): 23 incidents
├── DE.CM (Security Monitoring): 89 incidents
├── DE.DP (Detection Processes): 12 incidents
└── Coverage: 78% of categories have incidents
```

## CI Maintenance

### Weekly Tasks
- [ ] Review Detection Analytics for accuracy
- [ ] Update MITRE ATT&CK mappings for new techniques
- [ ] Validate KB article links (check for broken URLs)
- [ ] Update DeTT&CT coverage matrix

### Monthly Tasks
- [ ] Audit CI relationships for completeness
- [ ] Review and update RE&CT action templates
- [ ] Generate NIST CSF compliance report
- [ ] Update PICERL phase mappings based on workflow changes

### Quarterly Tasks
- [ ] Full CI inventory audit
- [ ] Detection coverage assessment
- [ ] Knowledge base effectiveness review
- [ ] Framework mapping validation (CSF, PICERL)

## CI Naming Conventions

### Detection Analytics
- Format: `ANALYTIC-{3-digit-ID}`
- Example: `ANALYTIC-001`, `ANALYTIC-042`

### MITRE ATT&CK
- Tactics: Use official names (e.g., "Initial Access")
- Techniques: Use T-codes (e.g., "T1566.001")

### RE&CT Actions
- Format: `RA{4-digit-ID}`
- Example: `RA3101`, `RA4201`

### Knowledge Base
- Format: `KB-{4-digit-ID}` or Confluence URL
- Example: `KB-0042` or `https://confluence.company.com/...`

### NIST CSF
- Format: `{Function}.{Category}-{ID}`
- Example: `DE.CM-7`, `RS.RP-1`

### DeTT&CT
- Format: `DETTCT-{ID}` or `Coverage-{Date}`
- Example: `DETTCT-Q1-2025`

## Benefits of CI Integration

### For Analysts
- Faster incident response (linked playbooks)
- Better context (MITRE ATT&CK mapping)
- Guided response (RE&CT actions)
- Knowledge at fingertips (KB links)

### For Management
- Visibility into detection coverage
- Framework compliance tracking (NIST CSF)
- Incident response maturity (PICERL)
- ROI measurement (detection efficacy)

### For Security Engineering
- Identify detection gaps
- Prioritize analytic development
- Validate detection effectiveness
- Track framework alignment

## Next Steps

1. **Implement CI Custom Fields** - See [JIRA Configuration](../docs/jira/CONFIGURATION-ITEMS.md)
2. **Populate Initial CIs** - Start with detection analytics and KB articles
3. **Configure Automation** - Set up auto-linking rules
4. **Train Team** - Educate analysts on CI usage
5. **Deploy Dashboards** - Create CI-based analytics dashboards

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Owner**: SOC Engineering Team
