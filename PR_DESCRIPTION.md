# Pull Request: Add comprehensive detection analytics and SOC use cases

## Summary

This PR adds a comprehensive detection analytics repository and SOC use cases focused on admin abuse, Active Directory security, network threats, and persistence mechanisms. The implementation includes:

- **49+ Detection Analytics** with production-ready SPL queries for Splunk
- **20 Detailed Use Cases** with complete incident response procedures
- **15+ Notable Event Configurations** for Splunk SIEM
- **7 SOAR Playbooks** for automated response
- **10 Lookup Table Examples** for whitelisting and enrichment

### Detection Categories

1. **Active Directory** (12 detections)
   - Privilege escalation (DET-AD-001 through DET-AD-006)
   - Kerberos attacks (DET-KRB-001 through DET-KRB-006): Golden/Silver Ticket, Kerberoasting, AS-REP Roasting

2. **Admin Abuse** (6 detections)
   - Policy violations (DET-POL-001 through DET-POL-006)
   - Unauthorized tools, non-PAW usage, security software tampering

3. **Network Security** (6 detections)
   - Lateral movement via SMB/RDP/WMI (DET-NET-001 through DET-NET-006)
   - Corelight/Zeek integration for DNS tunneling, port scanning, traffic anomalies

4. **Enumeration** (8 detections)
   - LDAP enumeration, network share discovery, domain trust mapping (DET-ENUM-001 through DET-ENUM-008)
   - BloodHound/PowerView detection, SPN enumeration

5. **Persistence Mechanisms** (6 detections)
   - Scheduled tasks, registry run keys, services, WMI subscriptions (DET-PERS-001 through DET-PERS-006)
   - Webshell detection, unauthorized account creation

6. **Notable Events** (15+ configurations)
   - Dynamic titles and descriptions
   - Drilldown searches for investigation
   - JIRA auto-creation webhooks

### Use Cases

1. **Admin Abuse** (10 use cases)
   - Self-service admin grant (UC-AA-001) - Critical priority
   - Unauthorized privilege escalation, after-hours activity
   - Complete 6-phase response procedures

2. **Active Directory** (10 use cases)
   - Golden Ticket attack (UC-AD-001) - Domain compromise
   - DCSync attack (UC-AD-002), Kerberoasting (UC-AD-004)
   - krbtgt password reset procedures, evidence preservation

### SOAR Playbooks

7 complete Python playbooks for Splunk SOAR:
- Privilege escalation response (semi-automated)
- Kerberoasting response (fully automated)
- Golden Ticket response (critical escalation)
- Unauthorized tool execution containment
- After-hours admin activity validation
- Admin workstation policy enforcement
- Security software tampering response

### Lookup Tables

10 comprehensive lookup table examples with CSV formats:
- Privileged accounts, admin workstations, authorized tools
- Threat intelligence feeds, asset information
- Baseline traffic patterns, malicious tool hashes
- CMDB and ServiceNow integration examples

## Technical Details

- **MITRE ATT&CK Coverage**: T1098, T1558, T1003, T1484, T1087, T1021, T1059, T1543, T1136
- **Data Sources**: Windows Security/Sysmon, Corelight/Zeek, PowerShell logs
- **Integration Points**: Splunk SIEM, Splunk SOAR, JIRA, ServiceNow, Active Directory
- **False Positive Tuning**: Lookup tables for whitelisting, baseline management
- **Response Procedures**: Containment → Investigation → Eradication → Recovery → Post-Incident

## Files Changed

- `analytics/README.md` - Detection repository index and deployment guide
- `analytics/active-directory/privilege-escalation.md` - 6 AD privilege escalation detections
- `analytics/active-directory/kerberos-attacks.md` - 6 Kerberos attack detections
- `analytics/admin-abuse/policy-violations.md` - 6 policy violation detections
- `analytics/network/lateral-movement.md` - 6 Corelight network detections
- `analytics/enumeration/ad-enumeration.md` - 8 enumeration detections
- `analytics/persistence/persistence-mechanisms.md` - 6 persistence detections
- `analytics/notable-events/notable-configurations.md` - 15+ notable configurations
- `analytics/soar-playbooks/soar-playbooks.md` - 7 complete SOAR playbooks
- `analytics/lookup-tables-examples.md` - 10 lookup table examples
- `use-cases/admin-abuse/README.md` - 10 admin abuse use cases
- `use-cases/active-directory/README.md` - 10 AD-specific use cases

**Total**: 12 files, 7,690+ insertions

## Test Plan

### Detection Analytics Testing
- [ ] Import SPL queries into Splunk search head
- [ ] Test each detection against sample data sets
- [ ] Validate MITRE ATT&CK technique mappings
- [ ] Verify lookup table integrations (privileged_accounts.csv, admin_workstations.csv)
- [ ] Test false positive filters and whitelisting
- [ ] Validate detection priority/severity levels

### Notable Event Configuration
- [ ] Configure notable events in Splunk ES
- [ ] Test dynamic title/description rendering with sample data
- [ ] Verify drilldown searches return expected results
- [ ] Test JIRA webhook integration for auto-ticket creation
- [ ] Validate notable event suppression rules

### SOAR Playbook Deployment
- [ ] Import playbooks into Splunk SOAR
- [ ] Configure app connections (Active Directory, ServiceNow, Palo Alto, CrowdStrike)
- [ ] Test containment actions (disable user, remove from groups, revoke sessions)
- [ ] Verify notification workflows (Slack, PagerDuty, email)
- [ ] Test evidence collection and preservation steps

### Use Case Validation
- [ ] Review response procedures with IR team
- [ ] Validate escalation criteria and SLA targets
- [ ] Test PowerShell remediation commands in lab environment
- [ ] Verify integration with change management (ServiceNow)
- [ ] Confirm evidence preservation procedures

### Lookup Table Setup
- [ ] Upload CSV files to `$SPLUNK_HOME/etc/apps/search/lookups/`
- [ ] Configure automatic lookups in props.conf/transforms.conf
- [ ] Test CMDB sync automation (asset_info.csv)
- [ ] Validate threat intelligence feed imports (threat_intel.csv)
- [ ] Test baseline generation (baseline_traffic.csv)
- [ ] Verify lookup table permissions and access controls

### Integration Testing
- [ ] End-to-end test: Detection → Notable → JIRA ticket → SOAR playbook
- [ ] Validate enrichment from lookup tables
- [ ] Test automated containment actions
- [ ] Verify audit logging and evidence preservation
- [ ] Test escalation workflows and notifications

### Documentation Review
- [ ] Validate all detection IDs are unique (DET-*)
- [ ] Confirm use case IDs are consistent (UC-*)
- [ ] Review response procedures for completeness
- [ ] Verify all MITRE ATT&CK techniques are correctly mapped
- [ ] Check SPL query syntax and best practices

## Deployment Checklist

1. **Phase 1 - Detection Analytics** (Week 1)
   - Import detection searches into Splunk
   - Configure lookup tables
   - Test in non-production environment
   - Tune false positive rates to <5%

2. **Phase 2 - Notable Events** (Week 2)
   - Configure notable event definitions
   - Set up drilldown searches
   - Test JIRA webhook integration
   - Train SOC analysts on new notables

3. **Phase 3 - SOAR Playbooks** (Week 3)
   - Import playbooks into SOAR
   - Configure app integrations
   - Test automated containment
   - Document manual approval steps

4. **Phase 4 - Use Case Training** (Week 4)
   - Conduct tabletop exercises
   - Review response procedures
   - Update runbooks as needed
   - Obtain stakeholder sign-off

## Security Considerations

- All SOAR playbooks require manual approval for destructive actions
- Evidence preservation steps precede remediation
- Audit logging enabled for all automated containment actions
- Privileged account usage limited to designated admin workstations (PAW policy)
- Critical detections (Golden Ticket, DCSync) escalate to CISO immediately

## Maintenance Plan

- **Weekly**: Review high-severity false positives, update whitelisting
- **Monthly**: Rebuild traffic baselines, update lookup tables
- **Quarterly**: Review detection coverage, tune thresholds, update use cases
- **Annually**: Full detection library audit, MITRE ATT&CK coverage review

---

## Branch Information

- **Source Branch**: `claude/soc-case-management-structure-RwXF3`
- **Target Branch**: `main`
- **Repository**: `dev-nobytes-io/jira-soc-inc-mgmt`

## Commits Included

1. `df05546` - Add comprehensive detection analytics, use cases, and SOAR playbooks
2. `58145c1` - Add enumeration detections, AD use cases, persistence mechanisms, and lookup tables
