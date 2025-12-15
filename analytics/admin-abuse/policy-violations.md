# Admin Policy Violation Detections

## Overview

Detections for administrative policy violations including unauthorized tool usage, policy breaches, and suspicious admin behavior.

---

## DET-POL-001: Unauthorized Admin Tool Execution

### Overview
- **Detection ID**: DET-POL-001
- **MITRE ATT&CK**: T1588.002 (Tool), T1078 (Valid Accounts)
- **Severity**: High
- **Data Sources**: Sysmon, Windows Security

### Description

Detects execution of administrative and hacking tools by users or on systems where they are not authorized, including PSExec, PsTools, Mimikatz, PowerView, etc.

### SPL Query

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval tool_category=case(
    match(Image, "(?i)(mimikatz|pwdump|gsecdump|wce\.exe|fgdump)"), "Credential Dumping",
    match(Image, "(?i)(psexec|paexec|psexesvc|remcom)"), "Remote Execution",
    match(Image, "(?i)(procdump|dumpert|nanodump)"), "Process Dumping",
    match(Image, "(?i)(powerview|sharphound|bloodhound|adexplorer)"), "AD Enumeration",
    match(Image, "(?i)(covenant|empire|metasploit|cobalt)"), "C2 Framework",
    match(Image, "(?i)(nmap|masscan|angry.*scan)"), "Network Scanning",
    match(CommandLine, "(?i)(invoke-mimikatz|invoke-bloodhound|get-domain)"), "PowerShell Attack Tool",
    match(CommandLine, "(?i)(net user.*\/add|net localgroup.*\/add)"), "Account Manipulation",
    1=1, null()
)
| where isnotnull(tool_category)
| search NOT [ | inputlookup authorized_admin_tools.csv | fields User, Image ]
| table _time, ComputerName, User, Image, CommandLine, ParentImage, tool_category, Hashes
| eval description="Unauthorized administrative or hacking tool execution detected"
| sort - _time
```

### Notable Event Configuration

```
Title: Unauthorized Admin Tool - $tool_category$ - $User$ on $ComputerName$
Description: User $User$ executed unauthorized tool on $ComputerName$:
Tool: $Image$
Category: $tool_category$
Command: $CommandLine$
Parent Process: $ParentImage$

This tool is not authorized for this user/system per security policy.

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1588.002, T1078

Recommended Actions:
1. Isolate $ComputerName$ immediately
2. Disable account $User$ pending investigation
3. Determine how tool was obtained/installed
4. Check for data exfiltration or credential theft
5. Investigate all recent activity by $User$
6. Scan for additional malware/tools
7. Create incident ticket and escalate
```

### Authorized Tools Whitelist

Create `authorized_admin_tools.csv`:
```csv
User,Image,Justification,Approved_By,Expiration
security_admin,C:\Tools\nmap.exe,Authorized vulnerability scanning,Security Manager,2025-12-31
red_team_user,C:\Tools\mimikatz.exe,Authorized penetration testing,CISO,2025-12-31
soc_analyst,C:\Tools\psexec.exe,Incident response tool,SOC Lead,2026-12-31
```

### Enhanced Detection - Hash-Based

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=Hashes "SHA256=(?<sha256>\w+)"
| lookup malicious_tool_hashes.csv sha256 OUTPUT tool_name, severity
| where isnotnull(tool_name)
| table _time, ComputerName, User, Image, tool_name, severity, CommandLine
| eval description="Known malicious tool hash detected"
```

### False Positives

1. **IT Administration**: Legitimate admin tool usage
2. **Security Testing**: Authorized penetration testing
3. **Incident Response**: SOC using tools during investigation

**Tuning**:
- Maintain whitelist of authorized users/tools
- Track expiration dates for approvals
- Geographic/network restrictions (only from jump boxes)

### Response Actions

**Immediate**:
1. Isolate endpoint
2. Disable user account
3. Preserve evidence (don't reboot)
4. Capture memory dump

**Investigation**:
1. Determine tool source
2. Check for credential theft
3. Review all recent user activity
4. Search for other tools
5. Check for lateral movement

**Playbook**: [Unauthorized Tool Usage Response](../../playbooks/admin-abuse/unauthorized-tools.md)

### SOAR Integration

```python
# Unauthorized tool execution response

# 1. Immediate containment
phantom.isolate_endpoint(hostname=computer_name)

# 2. Disable user
phantom.disable_user(user=user_name)

# 3. Evidence collection
phantom.collect_memory_dump(hostname=computer_name)
phantom.collect_process_info(hostname=computer_name, process=image)

# 4. Hash reputation check
phantom.check_file_reputation(hash=sha256)

# 5. Threat hunting
phantom.hunt_for_hash(hash=sha256, scope="enterprise")

# 6. Create critical incident
phantom.create_incident(
    severity="high",
    title=f"Unauthorized tool execution: {tool_category} by {user_name}",
    category="Policy Violation"
)
```

---

## DET-POL-002: Admin Activity from Non-Admin Workstation

### Overview
- **Detection ID**: DET-POL-002
- **MITRE ATT&CK**: T1078.002 (Domain Accounts)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs

### Description

Detects privileged account usage from workstations that are not designated admin workstations, violating least privilege and jump box policies.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| lookup privileged_accounts.csv Account_Name AS TargetUserName OUTPUT is_privileged, role
| where is_privileged="true"
| lookup admin_workstations.csv ComputerName OUTPUT is_admin_ws
| where isnull(is_admin_ws) OR is_admin_ws="false"
| table _time, TargetUserName, ComputerName, IpAddress, role, Logon_Type
| eval description="Privileged account used from unauthorized workstation"
| sort - _time
```

### Lookup Tables

**privileged_accounts.csv**:
```csv
Account_Name,is_privileged,role,Department
domain_admin01,true,Domain Administrator,IT
enterprise_admin,true,Enterprise Administrator,IT
helpdesk_user,false,Help Desk,Support
```

**admin_workstations.csv**:
```csv
ComputerName,is_admin_ws,Purpose,Owner
ADMIN-WS-001,true,Domain Admin Jump Box,IT Security
ADMIN-WS-002,true,Enterprise Admin Jump Box,IT Security
PAW-001,true,Privileged Access Workstation,IT
```

### Notable Event Configuration

```
Title: Admin Account Used from Non-Admin Workstation - $TargetUserName$
Description: Privileged account $TargetUserName$ ($role$) logged into $ComputerName$ from $IpAddress$.
This system is NOT a designated admin workstation per policy.

Policy: Privileged accounts must only be used from designated PAW/Jump boxes.

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1078.002

Recommended Actions:
1. Contact $TargetUserName$ immediately to verify activity
2. Terminate session if unauthorized
3. Review all actions performed during session
4. If compromise suspected, disable account
5. Remind user of admin workstation policy
6. Document violation for compliance
```

### Enhanced Query - Detect Admin Logons to User Workstations

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 (Logon_Type=2 OR Logon_Type=7 OR Logon_Type=10)
| lookup privileged_accounts.csv Account_Name AS TargetUserName OUTPUT is_privileged
| where is_privileged="true"
| rex field=ComputerName "^(?<ws_prefix>[A-Z]+)-"
| where NOT match(ws_prefix, "^(ADMIN|PAW|JUMP)")
| stats count, values(Logon_Type) as logon_types, values(IpAddress) as source_ips by TargetUserName, ComputerName
| eval description="Admin account logged into standard user workstation"
```

### Response Actions

1. Verify with account owner
2. Terminate session if unauthorized
3. Review session activity
4. Policy education/remediation
5. Consider account compromise if unusual

---

## DET-POL-003: Privileged Account Used for Non-Admin Tasks

### Overview
- **Detection ID**: DET-POL-003
- **MITRE ATT&CK**: T1078 (Valid Accounts)
- **Severity**: Medium
- **Data Sources**: Proxy Logs, Windows Event Logs

### Description

Detects privileged accounts being used for non-administrative tasks such as web browsing, email, or general productivity work, which violates security best practices.

### SPL Query - Web Browsing

```spl
index=proxy
| lookup privileged_accounts.csv Account_Name AS user OUTPUT is_privileged, role
| where is_privileged="true"
| search NOT [ | inputlookup approved_admin_sites.csv | fields url ]
| stats count, dc(url) as unique_sites, values(url) as sites_visited by user, src_ip
| where unique_sites > 5
| eval description="Privileged account used for web browsing"
| table _time, user, role, src_ip, count, unique_sites, sites_visited
```

### SPL Query - Email Usage

```spl
index=o365 sourcetype="o365:management:activity" Operation="Send"
| lookup privileged_accounts.csv Account_Name AS UserId OUTPUT is_privileged, role
| where is_privileged="true"
| stats count by UserId, role, ClientIP
| where count > 10
| eval description="Privileged account sending emails - policy violation"
```

### SPL Query - Productivity Application Usage

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| lookup privileged_accounts.csv Account_Name AS User OUTPUT is_privileged
| where is_privileged="true"
| eval app_type=case(
    match(Image, "(?i)(outlook|thunderbird)\.exe"), "Email Client",
    match(Image, "(?i)(chrome|firefox|edge|iexplore)\.exe"), "Web Browser",
    match(Image, "(?i)(winword|excel|powerpnt)\.exe"), "Office Apps",
    match(Image, "(?i)(teams|slack|zoom)\.exe"), "Communication Apps",
    1=1, null()
)
| where isnotnull(app_type)
| stats count by User, ComputerName, app_type, Image
| eval description="Admin account used for non-administrative productivity apps"
```

### Notable Event Configuration

```
Title: Privileged Account Used for Non-Admin Tasks - $user$
Description: Privileged account $user$ ($role$) was used for non-administrative activities:
Activity type: $app_type$ / Web browsing
From: $src_ip$ / $ComputerName$
Volume: $count$ events

Policy Violation: Privileged accounts must only be used for administrative tasks.

Severity: medium
Urgency: medium
Security Domain: access
MITRE ATT&CK: T1078

Recommended Actions:
1. Contact user to educate on policy
2. Review activity for suspicious behavior
3. Determine if account compromise
4. Document policy violation
5. Require user to use standard account for non-admin tasks
```

### Approved Sites Whitelist

`approved_admin_sites.csv`:
```csv
url,Category,Justification
vendors.microsoft.com,Vendor Portal,Admin tool downloads
portal.azure.com,Cloud Admin,Azure administration
*.vmware.com,Vendor Portal,Virtualization admin
*.atlassian.net,ITSM,JIRA/Confluence access
```

### Response Actions

1. Contact user to verify
2. Education on policy
3. Determine if compromise
4. Document violation
5. Recurring violations → disciplinary action

---

## DET-POL-004: Administrator Account Logging into User Workstation

### Overview
- **Detection ID**: DET-POL-004
- **MITRE ATT&CK**: T1078.002 (Domain Accounts)
- **Severity**: High
- **Data Sources**: Windows Security Event Logs

### Description

Detects when administrator accounts log into standard user workstations, which creates credential exposure risk.

### SPL Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624 (Logon_Type=2 OR Logon_Type=10)
| rex field=TargetUserName "(?<account_type>admin|adm|root|administrator)"
| where isnotnull(account_type)
| rex field=ComputerName "^(?<prefix>[A-Z]+)-"
| where prefix!="ADMIN" AND prefix!="PAW" AND prefix!="JUMP" AND prefix!="DC" AND prefix!="SRV"
| table _time, TargetUserName, ComputerName, IpAddress, Logon_Type, prefix
| eval description="Administrator account logged into user workstation"
| sort - _time
```

### Alternative Detection - Naming Convention

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4624
| eval is_admin_account=if(match(TargetUserName, "(?i)(adm_|admin_|_admin|administrator|root)"), "true", "false")
| eval is_user_workstation=if(match(ComputerName, "(?i)^(WS-|DESK-|LAPTOP-|PC-)"), "true", "false")
| where is_admin_account="true" AND is_user_workstation="true"
| table _time, TargetUserName, ComputerName, IpAddress, Logon_Type
| eval description="Admin naming convention account on user workstation"
```

### Notable Event Configuration

```
Title: Administrator Account on User Workstation - $TargetUserName$ -> $ComputerName$
Description: Administrator account $TargetUserName$ logged into user workstation $ComputerName$ from $IpAddress$.

Security Risk: Admin credentials exposed on potentially less secure user endpoint.

Policy: Administrator accounts must not be used to log into standard user workstations.

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1078.002

Recommended Actions:
1. Terminate session immediately
2. Contact user to determine reason
3. If legitimate need, use standard account instead
4. Check for credential theft/exposure
5. Force password change for admin account
6. Education on admin account usage policy
```

### Response Actions

1. Terminate session
2. Contact user immediately
3. Determine legitimate need
4. Force password change
5. Policy education

---

## DET-POL-005: Unapproved Remote Access Tool Usage

### Overview
- **Detection ID**: DET-POL-005
- **MITRE ATT&CK**: T1219 (Remote Access Software)
- **Severity**: High
- **Data Sources**: Sysmon, Windows Security, Network Traffic

### Description

Detects installation or usage of unapproved remote access tools such as TeamViewer, AnyDesk, RemotePC, etc.

### SPL Query - Process Execution

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval remote_tool=case(
    match(Image, "(?i)teamviewer"), "TeamViewer",
    match(Image, "(?i)anydesk"), "AnyDesk",
    match(Image, "(?i)logmein"), "LogMeIn",
    match(Image, "(?i)gotomypc"), "GoToMyPC",
    match(Image, "(?i)ammyy"), "Ammyy Admin",
    match(Image, "(?i)supremo"), "Supremo",
    match(Image, "(?i)remotepc"), "RemotePC",
    match(Image, "(?i)screenconnect"), "ScreenConnect",
    match(Image, "(?i)splashtop"), "Splashtop",
    match(Image, "(?i)(vnc|tightvnc|ultravnc|realvnc)"), "VNC",
    1=1, null()
)
| where isnotnull(remote_tool)
| search NOT [ | inputlookup approved_remote_tools.csv | fields User, remote_tool, ComputerName ]
| table _time, ComputerName, User, remote_tool, Image, CommandLine, ParentImage
| eval description="Unapproved remote access tool detected"
| sort - _time
```

### SPL Query - Network Detection

```spl
index=network sourcetype=corelight OR sourcetype=zeek
| eval remote_tool_domain=case(
    match(query, "(?i)teamviewer\.com"), "TeamViewer",
    match(query, "(?i)anydesk\.com"), "AnyDesk",
    match(query, "(?i)logmein\.com"), "LogMeIn",
    match(query, "(?i)gotomypc\.com"), "GoToMyPC",
    match(dest_port, "^(5938|7070|6568|5500)$"), "Common RAT Ports",
    1=1, null()
)
| where isnotnull(remote_tool_domain)
| stats count, values(src_ip) as sources, values(dest_ip) as destinations by remote_tool_domain
| eval description="Network traffic to unapproved remote access tool"
```

### SPL Query - Installation Detection

```spl
index=windows sourcetype="WinEventLog:Application" EventCode=11707 OR EventCode=11724
| eval product_name=if(match(Product_Name, "(?i)(teamviewer|anydesk|logmein|vnc)"), Product_Name, null())
| where isnotnull(product_name)
| table _time, ComputerName, User, product_name, Product_Version
| eval description="Unapproved remote access software installation"
```

### Notable Event Configuration

```
Title: Unapproved Remote Access Tool - $remote_tool$ on $ComputerName$
Description: Unapproved remote access tool detected:
Tool: $remote_tool$
System: $ComputerName$
User: $User$
Process: $Image$

Policy: Only approved remote access solutions are permitted. Unapproved tools pose security and compliance risks.

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1219

Recommended Actions:
1. Isolate $ComputerName$ from network
2. Terminate $remote_tool$ process
3. Investigate how tool was installed
4. Check for unauthorized remote access sessions
5. Scan for additional unauthorized software
6. Uninstall tool and educate user
7. Review user activity for suspicious behavior
```

### Approved Remote Tools

`approved_remote_tools.csv`:
```csv
User,remote_tool,ComputerName,Justification,Approved_By,Expiration
support_team,TeamViewer,SUPPORT-*,Customer support,IT Manager,2025-12-31
admin_user,ScreenConnect,ADMIN-*,IT Administration,CISO,2026-01-01
```

### Response Actions

**Immediate**:
1. Isolate system
2. Terminate remote tool
3. Check for active sessions

**Investigation**:
1. Determine installation source
2. Check for unauthorized access
3. Review user activity
4. Scan for additional tools

**Remediation**:
1. Uninstall tool
2. User education
3. Policy reminder
4. Recurring violations → disciplinary

### SOAR Integration

```python
# Unapproved remote tool response

# 1. Containment
phantom.isolate_endpoint(hostname=computer_name)

# 2. Kill process
phantom.kill_process(hostname=computer_name, process_name=remote_tool)

# 3. Check for active connections
connections = phantom.get_network_connections(hostname=computer_name, process=remote_tool)

# 4. If active connections found - CRITICAL
if len(connections) > 0:
    phantom.create_critical_incident(
        title=f"Active unauthorized remote access: {remote_tool}",
        severity="critical"
    )
    phantom.notify_soc_lead(message="Active unauthorized remote session detected")

# 5. Uninstall software
phantom.uninstall_software(hostname=computer_name, software=remote_tool)

# 6. Evidence collection
phantom.collect_network_pcap(hostname=computer_name, duration="10m")
phantom.get_process_tree(hostname=computer_name, process=remote_tool)
```

---

## DET-POL-006: Disabled Security Software

### Overview
- **Detection ID**: DET-POL-006
- **MITRE ATT&CK**: T1562.001 (Disable or Modify Tools)
- **Severity**: High
- **Data Sources**: Windows Event Logs, Sysmon, EDR

### Description

Detects when security software (antivirus, EDR, firewall) is disabled, which is a policy violation and potential indicator of attack.

### SPL Query - Windows Defender

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational" EventCode=5001 OR EventCode=5010 OR EventCode=5012
| eval action=case(
    EventCode=5001, "Real-time protection disabled",
    EventCode=5010, "Scanning disabled",
    EventCode=5012, "Tamper protection disabled",
    1=1, "Unknown"
)
| table _time, ComputerName, User, action, EventCode
| eval description="Windows Defender protection disabled"
```

### SPL Query - Firewall Disabled

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" EventCode=2003 OR EventCode=2004
| eval profile=case(
    EventCode=2003, "Domain Profile",
    EventCode=2004, "All Profiles",
    1=1, "Unknown"
)
| table _time, ComputerName, User, profile, Modifying_Application
| eval description="Windows Firewall disabled"
```

### SPL Query - Service Stop via Command Line

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)(sc stop|net stop|Stop-Service).*(windefend|sense|mpssvc|wuauserv)")
| eval service_stopped=case(
    match(CommandLine, "(?i)windefend"), "Windows Defender",
    match(CommandLine, "(?i)sense"), "Windows Defender ATP",
    match(CommandLine, "(?i)mpssvc"), "Windows Firewall",
    match(CommandLine, "(?i)wuauserv"), "Windows Update",
    1=1, "Unknown Service"
)
| table _time, ComputerName, User, service_stopped, CommandLine, ParentImage
| eval description="Security service stopped via command line"
```

### Notable Event Configuration

```
Title: Security Software Disabled on $ComputerName$ - $service_stopped$
Description: Security software was disabled on $ComputerName$:
Service: $service_stopped$
Action: $action$
User: $User$
Command: $CommandLine$

Policy: Security software must remain enabled at all times. Disabling is a critical policy violation.

Severity: high
Urgency: critical
Security Domain: endpoint
MITRE ATT&CK: T1562.001

Recommended Actions:
1. IMMEDIATELY re-enable security software on $ComputerName$
2. Isolate system from network
3. Contact $User$ to determine reason
4. If unauthorized, assume compromise
5. Full endpoint scan and investigation
6. Check for malware execution during disabled period
7. Escalate to Incident Response Team if compromise suspected
```

### Response Actions

**Immediate**:
1. Re-enable security software remotely
2. Isolate if unable to re-enable
3. Contact user

**Investigation**:
1. Determine who/what disabled software
2. Check for malware execution
3. Review logs during disabled period
4. Full system scan

**Remediation**:
1. Ensure software re-enabled
2. Policy enforcement (prevent disabling)
3. User education or disciplinary action

---

## Summary - Policy Violation Detections

| Detection ID | Policy Area | Severity | FP Rate | Priority |
|--------------|-------------|----------|---------|----------|
| DET-POL-001 | Unauthorized Tools | High | Low | 1 |
| DET-POL-002 | Admin Workstation Policy | High | Medium | 2 |
| DET-POL-003 | Admin Account Misuse | Medium | Medium | 3 |
| DET-POL-004 | Credential Exposure | High | Medium | 2 |
| DET-POL-005 | Remote Access Tools | High | Low | 1 |
| DET-POL-006 | Security Software Tampering | High | Low | 1 |

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering & Compliance Team
