# Splunk Lookup Table Examples

## Overview

This document provides example CSV lookup tables referenced in detection analytics for whitelisting, baselining, and enrichment.

## Table of Contents

1. [Privileged Accounts](#privileged-accounts)
2. [Admin Workstations](#admin-workstations)
3. [Authorized Admin Additions](#authorized-admin-additions)
4. [Approved After-Hours Activity](#approved-after-hours-activity)
5. [Authorized Admin Tools](#authorized-admin-tools)
6. [Malicious Tool Hashes](#malicious-tool-hashes)
7. [Asset Information](#asset-information)
8. [Threat Intelligence](#threat-intelligence)
9. [Common Run Keys](#common-run-keys)
10. [Baseline Traffic](#baseline-traffic)

---

## Privileged Accounts

**File**: `privileged_accounts.csv`

**Purpose**: List of accounts with elevated privileges for monitoring

**Usage**:
- Admin abuse detection
- After-hours activity monitoring
- Privilege escalation detection

**Format**:
```csv
Account_Name,is_privileged,role,Department,Manager
admin_user01,true,Domain Administrator,IT Operations,John Smith
admin_user02,true,Enterprise Administrator,IT Security,Jane Doe
helpdesk_admin,false,Help Desk,IT Support,Bob Johnson
svc_backup,true,Backup Service Account,IT Operations,Automated
db_admin,true,Database Administrator,IT Database,Alice Williams
security_analyst01,false,Security Analyst,SOC,Mike Brown
```

**Maintenance**:
- Update monthly or when admin roles change
- Review for terminated employees
- Add new admin accounts immediately
- Validate department assignments

---

## Admin Workstations

**File**: `admin_workstations.csv`

**Purpose**: Designated systems for privileged account access

**Usage**:
- Detect admin account usage from unauthorized systems
- Enforce jump box policy
- Privileged Access Workstation (PAW) validation

**Format**:
```csv
ComputerName,is_admin_ws,Purpose,Owner,Location
ADMIN-WS-001,true,Domain Admin Jump Box,IT Security,DC1
ADMIN-WS-002,true,Enterprise Admin Jump Box,IT Security,DC2
PAW-001,true,Privileged Access Workstation,IT Operations,HQ
PAW-002,true,Privileged Access Workstation,IT Security,HQ
JUMP-BOX-01,true,Linux Admin Jump Server,Unix Team,DC1
SEC-ANALYST-01,false,Security Analyst Workstation,SOC,SOC-Floor
```

**Maintenance**:
- Update when admin workstations deployed/decommissioned
- Quarterly review of designated systems
- Ensure naming convention consistency

---

## Authorized Admin Additions

**File**: `approved_admin_additions.csv`

**Purpose**: Track approved privilege grants to reduce false positives

**Usage**:
- Privilege escalation detection (DET-AD-001)
- Change management validation
- Automated approvals

**Format**:
```csv
SubjectUserName,TargetUserName,Reason,Approved_By,Approval_Date,Expiration
admin_sa,new_admin_user,New Admin Onboarding - CHG0012345,IT Manager,2025-12-01,2025-12-31
automation_svc,backup_admin,Automated Provisioning Script,CISO,2025-01-01,2026-01-01
helpdesk_lead,temp_admin,Temporary Elevation for Project,IT Director,2025-12-10,2025-12-20
```

**Maintenance**:
- Clean up expired entries monthly
- Add entries from change management system
- Review automation account entries quarterly

**Integration with ServiceNow**:
```python
# Auto-populate from ServiceNow change tickets
import requests

response = requests.get(
    'https://company.service-now.com/api/now/table/change_request',
    params={'sysparm_query': 'state=approved^short_description CONTAINS privilege'},
    auth=('api_user', 'api_key')
)

# Parse and add to lookup
for change in response.json()['result']:
    # Add to approved_admin_additions.csv
```

---

## Approved After-Hours Activity

**File**: `approved_afterhours_activity.csv`

**Purpose**: Track approved maintenance and after-hours admin work

**Usage**:
- After-hours admin activity detection (DET-AD-004)
- Maintenance window exceptions
- On-call rotations

**Format**:
```csv
TargetUserName,date,start_time,end_time,reason,approved_by,ticket
admin_user01,2025-12-14,22:00,02:00,Scheduled Server Maintenance,Change Manager,CHG0012345
admin_user02,2025-12-15,18:00,22:00,Emergency Patch Deployment,IT Director,INC0098765
backup_admin,*,02:00,04:00,Weekly Backup Window,IT Manager,Recurring
oncall_admin,*,*,*,On-Call Rotation - December,SOC Lead,ONCALL-DEC-2025
```

**Wildcards**:
- `*` for date: Applies to all dates
- `*` for time: Applies to all times
- Use for recurring activities

**Maintenance**:
- Add entries from change management
- Clean up expired one-time entries weekly
- Update on-call rotation monthly

---

## Authorized Admin Tools

**File**: `authorized_admin_tools.csv`

**Purpose**: Whitelist approved security and admin tools

**Usage**:
- Unauthorized tool detection (DET-POL-001)
- Security testing approvals
- Red team/pen test authorizations

**Format**:
```csv
User,Image,SHA256,Justification,Approved_By,Start_Date,End_Date,Scope
security_analyst,C:\Tools\nmap.exe,5d41402abc4b2a76b9719d911017c592,Authorized vulnerability scanning,Security Manager,2025-01-01,2025-12-31,Internal network only
red_team_user,C:\Tools\mimikatz.exe,098f6bcd4621d373cade4e832627b4f6,Approved penetration testing,CISO,2025-12-01,2025-12-31,Test environment only
soc_analyst,C:\Tools\psexec.exe,ad0234829205b9033196ba818f7a872b,Incident response tool,SOC Lead,2025-01-01,2026-12-31,Production access
forensics_lead,C:\Tools\volatility.exe,5f4dcc3b5aa765d61d8327deb882cf99,Memory forensics,CISO,2025-01-01,2026-01-01,Evidence analysis only
```

**Best Practices**:
- Use file hashes for precise matching
- Include expiration dates for time-limited approvals
- Document scope restrictions
- Review quarterly
- Remove expired entries

---

## Malicious Tool Hashes

**File**: `malicious_tool_hashes.csv`

**Purpose**: Known malicious tool signatures

**Usage**:
- Tool execution detection
- Hash hunting
- Automated blocking

**Format**:
```csv
sha256,tool_name,severity,category,source,date_added
3b5cc1d0f7fc0e04f8ca8e1c1e0b4f4a...,Mimikatz,critical,credential_dumping,VirusTotal,2025-01-15
7c228e1e6f8f6d9a9e8f0c5e1c0b4f4a...,Cobalt Strike Beacon,critical,c2_framework,Internal IR,2025-02-20
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...,PsExec (Sysinternals),low,legitimate_tool,Microsoft,2024-01-01
b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7...,BloodHound,medium,enumeration,GitHub,2025-03-10
```

**Sources**:
- VirusTotal
- Internal incident response findings
- Threat intelligence feeds
- Security vendor reports

**Maintenance**:
- Add hashes from detected incidents
- Import from threat intelligence platforms
- Review and prune old entries annually
- Validate legitimate tool hashes

**Automated Update**:
```python
# Update from VirusTotal
import requests

hash_list = ["hash1", "hash2", "hash3"]

for hash in hash_list:
    response = requests.get(
        f'https://www.virustotal.com/api/v3/files/{hash}',
        headers={'x-apikey': 'YOUR_API_KEY'}
    )
    if response.json()['data']['attributes']['last_analysis_stats']['malicious'] > 5:
        # Add to malicious_tool_hashes.csv
```

---

## Asset Information

**File**: `asset_info.csv`

**Purpose**: Asset inventory with type and ownership

**Usage**:
- Asset categorization in detections
- Exception handling for special systems
- Ownership identification

**Format**:
```csv
ip,hostname,asset_type,owner,department,criticality,location
10.1.1.10,DC01,domain_controller,IT Operations,Infrastructure,critical,DC1
10.1.1.11,DC02,domain_controller,IT Operations,Infrastructure,critical,DC2
10.1.2.50,ADMIN-WS-001,admin_workstation,IT Security,Security,high,HQ
10.1.3.100,WS-USER-001,workstation,John Doe,Sales,low,Office-Floor2
10.1.4.10,VULN-SCAN-01,vulnerability_scanner,Security Team,Security,medium,DMZ
10.1.5.25,JUMP-BOX-01,jump_server,Unix Team,Infrastructure,high,DC1
10.2.1.50,APP-SERVER-01,application_server,Dev Team,Development,medium,Cloud
```

**Asset Types**:
- `domain_controller`: Domain controllers (exclude from many detections)
- `admin_workstation`: Designated admin workstations
- `jump_server`: SSH/RDP jump boxes
- `workstation`: Standard user workstations
- `server`: General servers
- `vulnerability_scanner`: Scanning tools (exclude from port scan detection)
- `backup_server`: Backup systems
- `monitoring_server`: SIEM, monitoring tools

**Maintenance**:
- Sync with CMDB daily/weekly
- Update on asset deployments/retirements
- Quarterly review for accuracy

**CMDB Integration**:
```python
# Sync from ServiceNow CMDB
import requests

response = requests.get(
    'https://company.service-now.com/api/now/table/cmdb_ci',
    params={'sysparm_fields': 'ip_address,name,ci_type,owned_by'},
    auth=('api_user', 'api_key')
)

# Update asset_info.csv
```

---

## Threat Intelligence

**File**: `threat_intel.csv`

**Purpose**: Known malicious IPs, domains, hashes

**Usage**:
- Enrich detections with threat context
- Auto-escalate known threats
- Block known bad infrastructure

**Format**:
```csv
indicator,indicator_type,threat_category,confidence,source,date_added,tags
185.220.101.45,ip,tor_exit_node,high,TorProject,2025-01-15,anonymization
malware.example.com,domain,malware_distribution,high,Internal IR,2025-02-20,malware;c2
198.51.100.42,ip,known_apt_infrastructure,medium,CISA,2025-03-10,apt29;russia
badactor.net,domain,phishing,high,PhishTank,2025-04-05,phishing;credential_theft
```

**Indicator Types**:
- `ip`: IP addresses
- `domain`: Domain names
- `url`: Full URLs
- `hash`: File hashes
- `email`: Email addresses

**Sources**:
- Commercial threat intel feeds
- Open source intel (OSINT)
- Internal incident response
- ISAC/ISAO sharing
- Government advisories (CISA, FBI)

**Automated Updates**:
```python
# Import from threat intel platform
import requests

# Example: MISP
response = requests.get(
    'https://misp.company.com/attributes/restSearch',
    headers={'Authorization': 'YOUR_API_KEY'},
    json={'type': ['ip-dst', 'domain']}
)

# Parse and add to threat_intel.csv
```

**Maintenance**:
- Daily updates from threat feeds
- Weekly review of high-confidence indicators
- Monthly pruning of old indicators (>90 days)
- Validate and de-duplicate entries

---

## Common Run Keys

**File**: `common_run_keys.csv`

**Purpose**: Baseline legitimate registry run keys

**Usage**:
- Registry run key persistence detection (DET-PERS-002)
- Reduce false positives from legitimate software

**Format**:
```csv
key_name,expected,vendor,description,added_date
SecurityHealth,true,Microsoft,Windows Security notifications,2024-01-01
OneDrive,true,Microsoft,OneDrive sync client,2024-01-01
VMware Tools,true,VMware,VMware Tools services,2024-01-01
CrowdStrike,true,CrowdStrike,EDR agent,2024-06-01
Zoom,true,Zoom,Zoom client auto-start,2024-01-01
Slack,true,Slack,Slack client,2024-01-01
```

**Building the Baseline**:
```powershell
# Collect from known-good systems
$computers = Get-ADComputer -Filter * -SearchBase "OU=GoldImages,DC=company,DC=com"

foreach ($computer in $computers) {
    $runKeys = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
        Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    # Export unique keys to CSV
}
```

**Maintenance**:
- Update when new software deployed enterprise-wide
- Review quarterly for legitimacy
- Remove keys for uninstalled software

---

## Baseline Traffic

**File**: `baseline_traffic.csv`

**Purpose**: Normal traffic baselines for anomaly detection

**Usage**:
- Abnormal traffic volume detection (DET-NET-006)
- Identify data exfiltration
- Detect C2 beaconing

**Format**:
```csv
id.orig_h,avg_MB_sent,avg_MB_received,max_MB_sent,max_MB_received,baseline_period
10.1.3.100,150,500,300,1000,30_days
10.1.3.101,200,450,400,900,30_days
10.1.4.50,50,100,100,200,30_days
10.1.5.10,1000,2000,2000,4000,30_days
```

**Building Baseline**:
```spl
index=corelight sourcetype=corelight_conn
| stats sum(orig_bytes) as total_sent, sum(resp_bytes) as total_received by id.orig_h, date_mday
| eval MB_sent=total_sent/1024/1024, MB_received=total_received/1024/1024
| stats avg(MB_sent) as avg_MB_sent, avg(MB_received) as avg_MB_received,
        max(MB_sent) as max_MB_sent, max(MB_received) as max_MB_received
    by id.orig_h
| outputlookup baseline_traffic.csv
```

**Maintenance**:
- Rebuild monthly to capture changing patterns
- Adjust for business cycle changes
- Account for seasonal variations
- Validate against known traffic patterns

---

## Lookup Table Management

### Creating Lookups in Splunk

```bash
# Upload CSV to Splunk
$SPLUNK_HOME/etc/apps/search/lookups/privileged_accounts.csv

# Define lookup in transforms.conf
[privileged_accounts]
filename = privileged_accounts.csv
```

### Automatic Lookup Definition

```conf
# props.conf
[source::WinEventLog:Security]
LOOKUP-privileged = privileged_accounts Account_Name OUTPUT is_privileged, role, Department
```

### Scheduled Baseline Updates

```spl
# Saved search to update baseline_traffic.csv daily
index=corelight sourcetype=corelight_conn earliest=-30d
| stats sum(orig_bytes) as total_sent, sum(resp_bytes) as total_received by id.orig_h, date_mday
| eval MB_sent=total_sent/1024/1024, MB_received=total_received/1024/1024
| stats avg(MB_sent) as avg_MB_sent, avg(MB_received) as avg_MB_received,
        max(MB_sent) as max_MB_sent, max(MB_received) as max_MB_received
    by id.orig_h
| outputlookup baseline_traffic.csv
```

**Schedule**: Daily at 2 AM

### Lookup Table Permissions

```conf
# metadata/default.meta
[lookups/privileged_accounts.csv]
access = read : [ * ], write : [ admin, soc_lead ]
export = system
```

### Version Control

Best practices:
- Store lookup tables in Git repository
- Track changes with commit messages
- Review changes before deployment
- Keep backup copies
- Document update procedures

```bash
# Git workflow for lookup updates
git add analytics/lookups/privileged_accounts.csv
git commit -m "Add new admin account: admin_user05"
git push origin main

# Deploy to Splunk
scp privileged_accounts.csv splunk@siem:/opt/splunk/etc/apps/search/lookups/
```

---

## Summary - Lookup Tables

| Lookup Table | Purpose | Update Frequency | Owner |
|--------------|---------|------------------|-------|
| privileged_accounts.csv | Track admin accounts | Monthly | IAM Team |
| admin_workstations.csv | Designated admin systems | Quarterly | IT Ops |
| approved_admin_additions.csv | Approved privilege grants | Daily (automated) | Change Mgmt |
| approved_afterhours_activity.csv | Maintenance windows | Weekly | Change Mgmt |
| authorized_admin_tools.csv | Approved security tools | Monthly | Security Team |
| malicious_tool_hashes.csv | Known bad tools | Daily (automated) | Threat Intel |
| asset_info.csv | Asset inventory | Daily (CMDB sync) | IT Ops |
| threat_intel.csv | Threat indicators | Daily (feed import) | Threat Intel |
| common_run_keys.csv | Baseline registry keys | Quarterly | IT Ops |
| baseline_traffic.csv | Network traffic baselines | Daily (automated) | NetOps |

---

**Documentation Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
