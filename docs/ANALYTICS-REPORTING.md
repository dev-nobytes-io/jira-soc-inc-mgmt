# Analytics & Reporting for SOC Configuration Items

## Overview

This document describes analytics, metrics, and reporting capabilities enabled by Configuration Items (CI) integration in the SOC case management system.

## Key Benefits

### For Analysts
- Faster incident response through linked playbooks and detection rules
- Better context with MITRE ATT&CK and framework mappings
- Guided response procedures via RE&CT actions
- Knowledge at fingertips with KB article integration

### For Management
- Visibility into detection coverage and effectiveness
- Framework compliance tracking (NIST CSF 2.0, PICERL)
- Incident response maturity metrics
- ROI measurement for security tools and processes

### For Security Engineering
- Identify detection gaps systematically
- Prioritize analytic development based on data
- Validate detection effectiveness with metrics
- Track framework alignment and improvement

## Analytics Categories

### 1. Detection Analytics & Coverage

#### 1.1 Detection Effectiveness Metrics

**True Positive Rate by Analytic**
```
Metric: (True Positives / Total Alerts) × 100

Query:
SELECT
  detection_analytics,
  COUNT(*) as total_alerts,
  SUM(CASE WHEN verdict = 'True Positive' THEN 1 ELSE 0 END) as true_positives,
  ROUND(SUM(CASE WHEN verdict = 'True Positive' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as tp_rate
FROM incidents
WHERE detection_analytics IS NOT NULL
GROUP BY detection_analytics
ORDER BY tp_rate DESC
```

**Insights**:
- Identify high-performing analytics (>80% TP rate)
- Flag low-performing analytics for tuning (<50% TP rate)
- Measure overall detection quality

**MTTR by Detection Analytic**
```
Metric: Average time from alert to closure

Query:
SELECT
  detection_analytics,
  AVG(TIMESTAMPDIFF(HOUR, created, resolved)) as avg_mttr_hours,
  COUNT(*) as incident_count
FROM incidents
WHERE detection_analytics IS NOT NULL
  AND resolved IS NOT NULL
GROUP BY detection_analytics
ORDER BY avg_mttr_hours ASC
```

**Insights**:
- Lower MTTR = more actionable detections
- Identify analytics requiring playbook improvements
- Measure detection-to-response efficiency

#### 1.2 MITRE ATT&CK Coverage

**Technique Detection Coverage**
```
Metric: % of ATT&CK techniques with detection

Calculation:
Coverage = (Techniques with Detection / Total Techniques) × 100

Query:
WITH technique_coverage AS (
  SELECT technique,
         COUNT(DISTINCT detection_analytics) as detection_count
  FROM attack_technique_mappings
  GROUP BY technique
)
SELECT
  COUNT(*) as total_techniques,
  SUM(CASE WHEN detection_count > 0 THEN 1 ELSE 0 END) as covered_techniques,
  ROUND(SUM(CASE WHEN detection_count > 0 THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as coverage_pct
FROM technique_coverage
```

**Dashboard**: ATT&CK Navigator heatmap with coverage visualization

**Top Observed Techniques**
```
Query:
SELECT
  mitre_attack_technique,
  COUNT(*) as incident_count,
  COUNT(DISTINCT detection_analytics) as detection_count,
  CASE WHEN COUNT(DISTINCT detection_analytics) > 0 THEN 'Covered' ELSE 'Gap' END as coverage_status
FROM incidents
WHERE mitre_attack_technique IS NOT NULL
GROUP BY mitre_attack_technique
ORDER BY incident_count DESC
LIMIT 20
```

**Insights**:
- Most common attack techniques
- Detection coverage for top techniques
- Prioritize gaps based on frequency

#### 1.3 DeTT&CT Coverage Scores

**Overall Detection Maturity**
```
Metric: Average DeTT&CT score across all techniques

Calculation:
Maturity = (Σ Technique Scores) / (Total Techniques × 5) × 100

Query:
SELECT
  AVG(detection_score) as avg_detection_score,
  AVG(data_source_score) as avg_data_source_score,
  AVG(visibility_score) as avg_visibility_score,
  COUNT(*) as total_techniques,
  ROUND(AVG(detection_score) / 5 * 100, 2) as maturity_pct
FROM dettact_scores
```

**Dashboard**: Maturity gauge with target line (>70%)

**Coverage by Tactic**
```
Query:
SELECT
  tactic,
  COUNT(*) as total_techniques,
  AVG(detection_score) as avg_detection_score,
  ROUND(AVG(detection_score) / 5 * 100, 2) as coverage_pct
FROM dettact_scores
  JOIN attack_techniques ON dettact_scores.technique_id = attack_techniques.id
GROUP BY tactic
ORDER BY coverage_pct ASC
```

**Insights**:
- Identify weakest tactics (lowest coverage)
- Prioritize gap closure by tactic
- Track improvement over time

### 2. Framework Compliance & Mapping

#### 2.1 NIST CSF 2.0 Compliance

**Incident Coverage by CSF Function**
```
Query:
SELECT
  nist_csf_function,
  COUNT(*) as incident_count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM incidents), 2) as pct_of_total
FROM incidents
WHERE nist_csf_function IS NOT NULL
GROUP BY nist_csf_function
ORDER BY incident_count DESC
```

**Dashboard**: Pie chart of incidents by CSF function

**CSF Category Coverage**
```
Query:
SELECT
  csf_category,
  COUNT(DISTINCT incident_id) as incident_count
FROM incident_csf_mappings
GROUP BY csf_category
ORDER BY incident_count DESC
```

**Insights**:
- Most active CSF categories
- Identify categories with no incidents (potential gaps)
- Align incident response with framework

#### 2.2 PICERL Phase Metrics

**Phase Duration Analysis**
```
Query:
SELECT
  AVG(containment_duration_hours) as avg_containment,
  AVG(eradication_duration_hours) as avg_eradication,
  AVG(recovery_duration_hours) as avg_recovery,
  AVG(total_duration_hours) as avg_total,
  percentile_cont(0.5) WITHIN GROUP (ORDER BY total_duration_hours) as median_total
FROM incident_picerl_metrics
WHERE severity = 'Critical'
```

**Dashboard**: Bar chart of avg duration per phase, segmented by severity

**Phase Bottleneck Analysis**
```
Query:
SELECT
  picerl_phase,
  COUNT(*) as stuck_count,
  AVG(phase_duration_hours) as avg_duration
FROM incidents
WHERE status_category = 'In Progress'
  AND phase_duration_hours > (
    SELECT AVG(phase_duration_hours) * 2
    FROM incidents
    WHERE picerl_phase = incidents.picerl_phase
  )
GROUP BY picerl_phase
ORDER BY stuck_count DESC
```

**Insights**:
- Identify phases where incidents get stuck
- Optimize processes for bottleneck phases
- Set realistic SLAs per phase

#### 2.3 RE&CT Action Tracking

**Most Common Response Actions**
```
Query:
SELECT
  react_action,
  COUNT(*) as usage_count,
  AVG(action_duration_minutes) as avg_duration,
  AVG(effectiveness_rating) as avg_effectiveness
FROM incident_react_actions
GROUP BY react_action
ORDER BY usage_count DESC
LIMIT 20
```

**Dashboard**: Table with action usage and effectiveness

**Action Effectiveness by Incident Type**
```
Query:
SELECT
  incident_category,
  react_action,
  COUNT(*) as incident_count,
  AVG(mttr_hours) as avg_mttr,
  AVG(effectiveness_rating) as avg_rating
FROM incidents
  JOIN incident_react_actions ON incidents.id = incident_react_actions.incident_id
GROUP BY incident_category, react_action
ORDER BY incident_category, avg_rating DESC
```

**Insights**:
- Most effective actions per incident type
- Optimize playbooks with best-performing actions
- Identify actions needing improvement

### 3. Knowledge Base Analytics

#### 3.1 KB Usage Metrics

**Top Referenced KB Articles**
```
Query:
SELECT
  kb_reference,
  kb_title,
  COUNT(*) as incident_count,
  AVG(playbook_effectiveness) as avg_rating,
  AVG(mttr_hours) as avg_mttr
FROM incidents
  JOIN kb_articles ON incidents.primary_playbook = kb_articles.kb_id
WHERE kb_reference IS NOT NULL
GROUP BY kb_reference, kb_title
ORDER BY incident_count DESC
LIMIT 10
```

**Dashboard**: Table with usage, rating, and MTTR

**KB Articles Without Usage**
```
Query:
SELECT
  kb_id,
  title,
  type,
  last_updated,
  DATEDIFF(CURRENT_DATE, last_updated) as days_since_update
FROM kb_articles
WHERE kb_id NOT IN (
  SELECT DISTINCT kb_reference
  FROM incidents
  WHERE created > DATE_SUB(CURRENT_DATE, INTERVAL 6 MONTH)
)
ORDER BY last_updated ASC
```

**Action**: Review for archival or promotion

#### 3.2 Playbook Effectiveness

**Effectiveness Rating Distribution**
```
Query:
SELECT
  playbook_effectiveness,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM incidents WHERE playbook_effectiveness IS NOT NULL), 2) as pct
FROM incidents
WHERE playbook_effectiveness IS NOT NULL
GROUP BY playbook_effectiveness
ORDER BY playbook_effectiveness DESC
```

**Dashboard**: Pie chart of ratings

**Low-Rated Playbooks**
```
Query:
SELECT
  primary_playbook,
  COUNT(*) as usage_count,
  AVG(playbook_effectiveness) as avg_rating,
  CASE
    WHEN AVG(playbook_effectiveness) < 3 THEN 'Needs Improvement'
    WHEN AVG(playbook_effectiveness) < 4 THEN 'Adequate'
    ELSE 'Good'
  END as status
FROM incidents
WHERE primary_playbook IS NOT NULL
  AND playbook_effectiveness IS NOT NULL
GROUP BY primary_playbook
HAVING AVG(playbook_effectiveness) < 4
ORDER BY avg_rating ASC
```

**Action**: Prioritize playbook updates

#### 3.3 Knowledge Gap Analysis

**Incident Categories Without Playbooks**
```
Query:
SELECT
  incident_category,
  COUNT(*) as incident_count,
  COUNT(DISTINCT primary_playbook) as playbook_count,
  ROUND(COUNT(DISTINCT CASE WHEN primary_playbook IS NOT NULL THEN id END) * 100.0 / COUNT(*), 2) as coverage_pct
FROM incidents
GROUP BY incident_category
HAVING coverage_pct < 100
ORDER BY incident_count DESC
```

**Action**: Create playbooks for high-volume categories without coverage

### 4. CI Relationship Analytics

#### 4.1 Detection → Response Chain

**Complete Chain Tracking**
```
Query:
SELECT
  d.detection_analytics,
  a.mitre_attack_technique,
  r.react_action,
  k.primary_playbook,
  COUNT(*) as incident_count,
  AVG(i.mttr_hours) as avg_mttr
FROM incidents i
  JOIN detection_analytics d ON i.detection_analytics = d.analytic_id
  LEFT JOIN attack_mappings a ON i.id = a.incident_id
  LEFT JOIN react_actions r ON i.id = r.incident_id
  LEFT JOIN kb_articles k ON i.primary_playbook = k.kb_id
GROUP BY d.detection_analytics, a.mitre_attack_technique, r.react_action, k.primary_playbook
ORDER BY incident_count DESC
```

**Dashboard**: Network graph showing relationships

**Chain Completeness**
```
Metric: % incidents with complete CI chain

Complete Chain = Detection + ATT&CK + RE&CT + KB

Query:
SELECT
  COUNT(*) as total_incidents,
  SUM(CASE WHEN detection_analytics IS NOT NULL THEN 1 ELSE 0 END) as with_detection,
  SUM(CASE WHEN mitre_attack_technique IS NOT NULL THEN 1 ELSE 0 END) as with_attack,
  SUM(CASE WHEN react_action IS NOT NULL THEN 1 ELSE 0 END) as with_react,
  SUM(CASE WHEN primary_playbook IS NOT NULL THEN 1 ELSE 0 END) as with_kb,
  SUM(CASE
        WHEN detection_analytics IS NOT NULL
         AND mitre_attack_technique IS NOT NULL
         AND react_action IS NOT NULL
         AND primary_playbook IS NOT NULL
        THEN 1 ELSE 0
      END) as complete_chain,
  ROUND(SUM(CASE
              WHEN detection_analytics IS NOT NULL
               AND mitre_attack_technique IS NOT NULL
               AND react_action IS NOT NULL
               AND primary_playbook IS NOT NULL
              THEN 1 ELSE 0
            END) * 100.0 / COUNT(*), 2) as completeness_pct
FROM incidents
WHERE incident_type = 'Incident'
```

**Target**: >90% completeness

#### 4.2 Framework Alignment

**Cross-Framework Mapping**
```
Query:
SELECT
  nist_csf_function,
  picerl_phase,
  COUNT(*) as incident_count,
  AVG(mttr_hours) as avg_mttr
FROM incidents
WHERE nist_csf_function IS NOT NULL
  AND picerl_phase IS NOT NULL
GROUP BY nist_csf_function, picerl_phase
ORDER BY incident_count DESC
```

**Dashboard**: Heatmap showing CSF × PICERL distribution

### 5. Trending & Predictive Analytics

#### 5.1 Technique Trends

**Emerging Techniques**
```
Query:
WITH monthly_counts AS (
  SELECT
    DATE_TRUNC('month', created) as month,
    mitre_attack_technique,
    COUNT(*) as count
  FROM incidents
  WHERE created > DATE_SUB(CURRENT_DATE, INTERVAL 6 MONTH)
  GROUP BY month, mitre_attack_technique
),
growth AS (
  SELECT
    mitre_attack_technique,
    AVG(count) as avg_monthly,
    (MAX(count) - MIN(count)) / NULLIF(MIN(count), 0) as growth_rate
  FROM monthly_counts
  GROUP BY mitre_attack_technique
)
SELECT
  mitre_attack_technique,
  ROUND(avg_monthly, 1) as avg_monthly_incidents,
  ROUND(growth_rate * 100, 2) as growth_rate_pct
FROM growth
WHERE growth_rate > 0.5  -- 50% growth
ORDER BY growth_rate DESC
LIMIT 10
```

**Action**: Prioritize detection development for emerging techniques

#### 5.2 Coverage Improvement Trends

**Quarterly Coverage Improvement**
```
Query:
SELECT
  EXTRACT(YEAR FROM assessment_date) as year,
  EXTRACT(QUARTER FROM assessment_date) as quarter,
  AVG(coverage_pct) as avg_coverage,
  COUNT(DISTINCT technique_id) as techniques_assessed
FROM dettact_assessments
GROUP BY year, quarter
ORDER BY year, quarter
```

**Dashboard**: Line chart showing coverage improvement over time

**Target**: 5% improvement per quarter

#### 5.3 Predictive Incident Volume

**Incident Volume Forecast**
```
Query (using linear regression or time series):
-- Requires analytics platform (e.g., Splunk, Tableau)
-- Or export to Python/R for analysis

SELECT
  DATE_TRUNC('week', created) as week,
  COUNT(*) as incident_count
FROM incidents
WHERE created > DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR)
GROUP BY week
ORDER BY week
```

**Use**: Capacity planning, staffing decisions

## Dashboard Catalog

### Executive Dashboard
**Purpose**: High-level metrics for leadership

**Widgets**:
1. Total Incidents (current month vs. last month)
2. MTTR Trend (line chart, 6 months)
3. Top 5 Incident Categories (pie chart)
4. Critical Incidents Status (table)
5. Detection Coverage Score (gauge)
6. Framework Compliance Summary (scorecard)

**Refresh**: Daily

---

### Detection Engineering Dashboard
**Purpose**: Detection performance and gaps

**Widgets**:
1. True Positive Rate by Analytic (bar chart)
2. Detection Coverage Heatmap (ATT&CK Navigator)
3. DeTT&CT Maturity Score (gauge)
4. Detection Gaps (table with priority)
5. Alert Volume Trend (line chart)
6. Top False Positive Sources (table)

**Refresh**: Hourly

---

### Incident Response Dashboard
**Purpose**: Operational metrics for SOC

**Widgets**:
1. Active Incidents by Phase (PICERL pie chart)
2. SLA Compliance (gauge)
3. Phase Duration (bar chart)
4. Incident Queue (table, sorted by age)
5. Escalation Rate (trend)
6. Playbook Usage (table)

**Refresh**: Real-time (5 min)

---

### Knowledge Management Dashboard
**Purpose**: KB effectiveness and gaps

**Widgets**:
1. Top 10 KB Articles (table with usage)
2. Playbook Effectiveness (bar chart)
3. KB Coverage by Category (table)
4. Unused KB Articles (table)
5. KB Freshness (gauge: % updated in last 6 months)
6. MTTR by Playbook (table)

**Refresh**: Weekly

---

### Framework Compliance Dashboard
**Purpose**: CSF, PICERL, ATT&CK alignment

**Widgets**:
1. NIST CSF Coverage (pie chart by function)
2. PICERL Maturity Scorecard
3. ATT&CK Coverage by Tactic (bar chart)
4. Framework Mapping Completeness (gauge)
5. RE&CT Action Usage (table)
6. Cross-Framework Heatmap (CSF × PICERL)

**Refresh**: Daily

---

## Reporting Schedule

### Daily Reports
- Overnight incident summary
- SLA compliance status
- Critical incident updates

### Weekly Reports
- Detection analytics performance
- Top techniques observed
- Playbook effectiveness
- Knowledge base usage

### Monthly Reports
- Executive summary
- Incident trend analysis
- Coverage improvement
- Framework compliance
- Action items for next month

### Quarterly Reports
- SOC maturity assessment
- DeTT&CT coverage review
- Strategic recommendations
- Budget/resource planning
- Framework alignment review

## Next Steps

1. **Deploy Dashboards** - Create dashboards in JIRA
2. **Schedule Reports** - Configure automated report generation
3. **Train Team** - Educate analysts on analytics usage
4. **Establish Baselines** - Document initial metrics
5. **Set Targets** - Define goals and KPIs
6. **Monitor & Improve** - Continuous optimization

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Analytics Team
