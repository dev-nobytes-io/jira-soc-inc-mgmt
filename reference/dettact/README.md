# DeTT&CT - Detect Tactics, Techniques & Combat Threats

## Overview

DeTT&CT (Detect Tactics, Techniques & Combat Threats) is a framework designed to help blue teams map their detection coverage against MITRE ATT&CK. It provides structured methods for assessing, scoring, and visualizing detection capabilities.

## What is DeTT&CT?

DeTT&CT helps answer critical questions:
- Which ATT&CK techniques can we detect?
- How mature is our detection for each technique?
- Where are our detection gaps?
- How has our detection coverage improved over time?
- What techniques should we prioritize for detection development?

## DeTT&CT Data Source Layers

### Layer 1: Data Sources Available
**Question**: Do we have the necessary log sources?

**Assessment Criteria**:
- 0: No data source available
- 1: Partially available (incomplete logging)
- 2: Available (full logging collection)
- 3: Available with high quality (enriched, normalized)

**Examples**:
```
Windows Event Logs:
  - Security logs (4624, 4625, 4688, etc.): Score 3 (full collection, enriched)
  - Sysmon logs: Score 3 (deployed on all endpoints)
  - PowerShell logs: Score 2 (enabled but not all systems)

Network:
  - Firewall logs: Score 3 (all traffic logged)
  - DNS logs: Score 2 (internal only, no external DNS)
  - Proxy logs: Score 1 (partial deployment)
```

### Layer 2: Detection Analytics
**Question**: Do we have detection rules/analytics?

**Assessment Criteria**:
- 0: No detection analytics
- 1: Basic detection (single indicator)
- 2: Moderate detection (correlation, context)
- 3: Advanced detection (behavioral, ML)
- 4: Advanced with tuning (low FP, high accuracy)
- 5: Exceptional (threat hunting, proactive)

**Examples**:
```
T1003.001 (LSASS Memory Dumping):
  - Data Source: Sysmon Event 10 (Score 3)
  - Detection: ANALYTIC-003 (Score 4)
    - Detects LSASS access
    - Excludes legitimate tools
    - Low false positive rate
    - Validated against real attacks

T1566.001 (Spearphishing Attachment):
  - Data Source: Email gateway logs (Score 3)
  - Detection: ANALYTIC-010 (Score 3)
    - Basic phishing indicators
    - Some false positives
    - Needs tuning
```

### Layer 3: Visibility Quality
**Question**: How good is our visibility into this technique?

**Assessment Criteria**:
- 0: No visibility
- 1: Minimal (limited data, blind spots)
- 2: Medium (partial coverage, some gaps)
- 3: Good (comprehensive coverage, minimal gaps)
- 4: Excellent (full coverage, high fidelity)

**Calculation**:
```
Visibility = MIN(Data Source Score, Detection Score)

If Data Source = 3 and Detection = 4:
  Visibility = 3 (limited by data quality)

If Data Source = 2 and Detection = 3:
  Visibility = 2 (limited by data availability)
```

### Layer 4: Detection Capability
**Question**: Can we effectively detect this technique in production?

**Assessment Criteria**:
Combines data sources, analytics, and operational factors:
- Coverage completeness
- Alert accuracy (low FP rate)
- Response time
- Operational maturity

**Scoring**:
- 0: Cannot detect
- 1: Minimal capability
- 2: Partial capability
- 3: Good capability
- 4: Excellent capability
- 5: Exceptional capability

## DeTT&CT Integration with JIRA

### Detection Maturity Levels

#### Level 0: No Detection
- No data sources available
- No detection analytics
- No visibility
- **Action**: Identify if needed, prioritize for implementation

#### Level 1: Initial
- Basic data sources available
- Simple detection rules
- High false positive rate
- Manual investigation required
- **JIRA**: Detection analytics in development, not production

#### Level 2: Developing
- Multiple data sources available
- Correlation rules deployed
- Moderate false positive rate
- Some automation
- **JIRA**: Detection analytics in production, tuning ongoing

#### Level 3: Defined
- Comprehensive data sources
- Advanced detection logic
- Low false positive rate
- Automated enrichment
- **JIRA**: Detection analytics validated, KB article exists

#### Level 4: Managed
- High-quality data sources
- Behavioral detection
- Very low false positive rate
- Automated response actions
- **JIRA**: Full automation from detection → containment

#### Level 5: Optimizing
- Exceptional data quality
- Threat hunting queries
- Proactive detection
- ML/AI-based detection
- Continuous improvement
- **JIRA**: Threat hunting use cases, purple team validation

### DeTT&CT Scoring in JIRA

#### Custom Field: DeTT&CT Detection Score
- **Type**: Single-select dropdown
- **Values**: 0, 1, 2, 3, 4, 5
- **Usage**: Score detection capability per technique
- **Updated**: During detection development, quarterly reviews

#### Custom Field: DeTT&CT Data Source Score
- **Type**: Single-select dropdown
- **Values**: 0, 1, 2, 3
- **Usage**: Score data source availability per technique
- **Updated**: During data source onboarding, quarterly reviews

#### Custom Field: DeTT&CT Visibility Score
- **Type**: Calculated field
- **Formula**: MIN(Data Source Score, Detection Score)
- **Usage**: Overall visibility assessment

### DeTT&CT Coverage Tracking

#### Technique Coverage Assessment
```
FOR EACH ATT&CK Technique:
  1. Identify required data sources
  2. Score data source availability (0-3)
  3. Identify detection analytics
  4. Score detection capability (0-5)
  5. Calculate visibility (MIN of above)
  6. Document in DeTT&CT layer
  7. Identify gaps
  8. Prioritize improvements
```

#### Coverage Matrix Example
```
| Technique | Data Source | Detection | Visibility | Status |
|-----------|-------------|-----------|------------|--------|
| T1003.001 | Sysmon (3) | ANALYTIC-003 (4) | 3 | ✓ Good |
| T1566.001 | Email GW (3) | ANALYTIC-010 (3) | 3 | ✓ Good |
| T1110.003 | Win Events (3) | ANALYTIC-002 (2) | 2 | ⚠ Needs tuning |
| T1047 | Sysmon (2) | ANALYTIC-004 (3) | 2 | ⚠ Data source gap |
| T1136.001 | Win Events (3) | None (0) | 0 | ✗ Detection gap |
```

## DeTT&CT YAML File Structure

### Technique Scoring File
```yaml
version: 1.0
name: "SOC Detection Coverage - Q4 2025"
domain: "enterprise-attack"
platform: "Windows"

techniques:
  - technique_id: "T1003.001"
    technique_name: "LSASS Memory"
    detection:
      - applicable_to: ["all"]
        location: "SIEM"
        comment: "ANALYTIC-003: Sysmon Event 10 monitoring"
        score_logbook:
          - date: 2025-12-14
            score: 4
            comment: "Advanced detection with low FP rate"
            auto_generated: false
    visibility:
      score_logbook:
        - date: 2025-12-14
          score: 3
          comment: "Good visibility via Sysmon"
          auto_generated: false

  - technique_id: "T1566.001"
    technique_name: "Spearphishing Attachment"
    detection:
      - applicable_to: ["all"]
        location: "Email Gateway"
        comment: "ANALYTIC-010: Phishing detection rules"
        score_logbook:
          - date: 2025-12-14
            score: 3
            comment: "Moderate detection, needs tuning"
            auto_generated: false
    visibility:
      score_logbook:
        - date: 2025-12-14
          score: 3
          comment: "Good visibility via email logs"
          auto_generated: false
```

### Data Source Availability File
```yaml
version: 1.0
name: "Data Source Availability Assessment"
date: 2025-12-14

data_sources:
  - name: "Windows Event Logs - Security"
    platforms: ["Windows"]
    collection: "Full"
    coverage: "All endpoints"
    quality: "High"
    score: 3
    comment: "Centralized collection via SIEM"

  - name: "Sysmon"
    platforms: ["Windows"]
    collection: "Full"
    coverage: "All endpoints"
    quality: "High"
    score: 3
    comment: "Deployed on all Windows systems"

  - name: "PowerShell Logs"
    platforms: ["Windows"]
    collection: "Partial"
    coverage: "70% of systems"
    quality: "Medium"
    score: 2
    comment: "Not enabled on all workstations"

  - name: "DNS Logs"
    platforms: ["Network"]
    collection: "Partial"
    coverage: "Internal DNS only"
    quality: "Medium"
    score: 2
    comment: "External DNS not logged"
```

## DeTT&CT Visualization

### ATT&CK Navigator Layer Export

Generate ATT&CK Navigator layer from DeTT&CT scores:

```json
{
  "name": "DeTT&CT Detection Coverage",
  "versions": {
    "navigator": "4.5",
    "layer": "4.3"
  },
  "domain": "enterprise-attack",
  "description": "Detection capability heatmap",
  "techniques": [
    {
      "techniqueID": "T1003.001",
      "score": 4,
      "comment": "ANALYTIC-003 deployed, good detection",
      "color": "#00ff00"
    },
    {
      "techniqueID": "T1566.001",
      "score": 3,
      "comment": "ANALYTIC-010 deployed, moderate detection",
      "color": "#ffff00"
    },
    {
      "techniqueID": "T1136.001",
      "score": 0,
      "comment": "No detection, gap identified",
      "color": "#ff0000"
    }
  ],
  "gradient": {
    "colors": ["#ff0000", "#ffff00", "#00ff00"],
    "minValue": 0,
    "maxValue": 5
  }
}
```

### Heatmap Color Coding
- **Red (0-1)**: No/minimal detection - HIGH PRIORITY
- **Yellow (2-3)**: Moderate detection - NEEDS IMPROVEMENT
- **Green (4-5)**: Good/excellent detection - MAINTAIN

## DeTT&CT Gap Analysis

### Identification Process

1. **Generate Coverage Layer**
   - Export current detection scores
   - Visualize in ATT&CK Navigator
   - Identify red/yellow areas

2. **Risk Assessment**
   ```
   FOR EACH Gap (score 0-2):
     Risk = Likelihood × Impact

     Likelihood factors:
       - Technique prevalence in threat landscape
       - Technique difficulty (easy = high likelihood)
       - Observed in past incidents

     Impact factors:
       - Business criticality
       - Data sensitivity
       - Potential damage
   ```

3. **Prioritization**
   ```
   Priority = Risk Score × Detectability

   Detectability factors:
     - Data source availability
     - Detection complexity
     - False positive potential
     - Implementation effort
   ```

4. **Gap Closure Planning**
   ```
   FOR EACH High-Priority Gap:
     1. Identify required data sources
     2. Design detection logic
     3. Estimate development effort
     4. Assign owner
     5. Set target date
     6. Track in JIRA
   ```

### Example Gap Analysis Report

```
CRITICAL GAPS (Score 0, High Risk):
┌─────────────┬──────────────────────────┬──────┬────────┬──────────┐
│ Technique   │ Name                     │ Risk │ Action │ Owner    │
├─────────────┼──────────────────────────┼──────┼────────┼──────────┤
│ T1136.001   │ Create Local Account     │ High │ Build  │ Det Eng  │
│ T1078.004   │ Cloud Accounts           │ High │ Build  │ Cloud Sec│
│ T1505.003   │ Web Shell                │ Med  │ Plan   │ Det Eng  │
└─────────────┴──────────────────────────┴──────┴────────┴──────────┘

IMPROVEMENT NEEDED (Score 1-2, Medium Risk):
┌─────────────┬──────────────────────────┬──────┬────────┬──────────┐
│ Technique   │ Name                     │ Risk │ Action │ Owner    │
├─────────────┼──────────────────────────┼──────┼────────┼──────────┤
│ T1110.003   │ Password Spraying        │ Med  │ Tune   │ SOC      │
│ T1047       │ WMI                      │ Med  │ Data   │ SysAdmin │
│ T1070.001   │ Clear Windows Event Logs │ Med  │ Build  │ Det Eng  │
└─────────────┴──────────────────────────┴──────┴────────┴──────────┘
```

## DeTT&CT Metrics & Reporting

### Coverage Metrics

```
Overall Coverage = (Σ Technique Scores) / (Total Techniques × 5) × 100

Example:
  Total Techniques: 100
  Sum of Scores: 280
  Max Possible: 500 (100 × 5)
  Coverage: (280/500) × 100 = 56%
```

### Coverage by Tactic
```
Tactic Coverage = (Σ Tactic Technique Scores) / (Tactic Techniques × 5) × 100

Example - Credential Access:
  Techniques: 15
  Sum of Scores: 48
  Max Possible: 75
  Coverage: (48/75) × 100 = 64%
```

### Coverage Trends
Track coverage improvement over time:

```
Quarter | Overall | Initial Access | Execution | Credential Access |
--------|---------|----------------|-----------|-------------------|
Q1 2025 | 48%     | 62%            | 71%       | 58%              |
Q2 2025 | 52%     | 68%            | 75%       | 61%              |
Q3 2025 | 56%     | 71%            | 78%       | 64%              |
Q4 2025 | 61%     | 75%            | 82%       | 68%              |
```

### Dashboard Widgets

#### Widget 1: Coverage Gauge
```
Type: Gauge chart
Metric: Overall detection coverage %
Target: > 70%
Current: 61%
Color: Red (<50%), Yellow (50-70%), Green (>70%)
```

#### Widget 2: Coverage by Tactic
```
Type: Bar chart
X-axis: ATT&CK Tactics
Y-axis: Coverage %
Purpose: Identify weak tactics
```

#### Widget 3: Gap Count by Priority
```
Type: Pie chart
Segments:
  - Critical gaps (score 0): 12
  - High priority (score 1): 18
  - Medium priority (score 2): 25
  - Low priority (score 3): 30
Purpose: Prioritize gap closure
```

#### Widget 4: Coverage Trend
```
Type: Line chart
X-axis: Time (quarterly)
Y-axis: Coverage %
Lines: Overall, by tactic
Purpose: Track improvement
```

## DeTT&CT Integration with JIRA Workflows

### Detection Development Workflow

```
1. Gap Identified (DeTT&CT score 0-2)
   ↓
2. JIRA Issue Created: "Detection Development - T####"
   - Type: Task
   - Priority: Based on risk assessment
   - Assigned: Detection Engineering
   ↓
3. Development Phase
   - Design detection logic
   - Identify data sources
   - Create ANALYTIC-XXX
   ↓
4. Testing Phase
   - Test in dev environment
   - Validate with purple team
   - Measure false positive rate
   ↓
5. Deployment Phase
   - Deploy to production
   - Monitor for 2 weeks
   - Tune as needed
   ↓
6. Coverage Update
   - Update DeTT&CT score
   - Update coverage layer
   - Close JIRA issue
   ↓
7. Validation
   - Quarterly review
   - Purple team exercise
   - Update score if needed
```

### Quarterly Coverage Review

```
1. Generate Current Coverage Report
   - Export DeTT&CT scores
   - Create ATT&CK Navigator layer
   - Calculate metrics

2. Gap Analysis
   - Identify new gaps
   - Reassess existing gaps
   - Update risk scores

3. Prioritization
   - Rank gaps by risk
   - Allocate resources
   - Set quarterly goals

4. Action Planning
   - Create JIRA issues for gaps
   - Assign owners
   - Set target dates

5. Tracking & Reporting
   - Monitor progress
   - Update coverage quarterly
   - Report to management
```

## DeTT&CT Tools & Resources

### DeTT&CT Framework
- GitHub: https://github.com/rabobank-cdc/DeTTECT
- Documentation: https://github.com/rabobank-cdc/DeTTECT/wiki
- Editor: DeTT&CT Editor (web-based tool)

### Integration Tools
- Python scripts for JIRA integration
- ATT&CK Navigator for visualization
- YAML editors for data source/technique files

### Community Resources
- DeTT&CT Blog Posts
- Detection Maturity Models
- Community Detection Scores

## Best Practices

### 1. Regular Assessment
- Quarterly coverage reviews
- Update scores after detection changes
- Track trends over time

### 2. Collaborative Scoring
- Include SOC analysts
- Involve detection engineers
- Get threat intel input
- Validate with purple team

### 3. Realistic Scoring
- Be honest about capabilities
- Don't inflate scores
- Document scoring rationale
- Track score changes

### 4. Gap Prioritization
- Focus on high-risk gaps
- Consider threat landscape
- Align with business priorities
- Balance quick wins and long-term goals

### 5. Continuous Improvement
- Set quarterly goals
- Celebrate improvements
- Learn from incidents
- Share lessons learned

## Implementation Guide

### Phase 1: Baseline Assessment
1. Inventory data sources
2. Score data source availability
3. Catalog detection analytics
4. Score detection capability
5. Generate baseline coverage report

### Phase 2: Gap Analysis
1. Identify gaps (score 0-2)
2. Assess risk
3. Prioritize gaps
4. Create action plan

### Phase 3: Improvement
1. Develop new detections
2. Improve data sources
3. Tune existing analytics
4. Update scores

### Phase 4: Validation
1. Purple team exercises
2. Incident validation
3. Score verification
4. Continuous monitoring

### Phase 5: Reporting
1. Generate coverage reports
2. Track trends
3. Management reporting
4. Team communication

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Framework**: DeTT&CT
**Maintained By**: Detection Engineering Team
