# Splunk Notable Event Configurations

## Overview

This document provides complete configurations for Splunk Enterprise Security notable events for all SOC detections.

## Notable Event Configuration Format

Each notable event includes:
- **Title**: Dynamic title with key variables
- **Description**: Detailed context for analysts
- **Severity**: critical, high, medium, low, informational
- **Security Domain**: access, endpoint, network, threat, identity
- **Urgency**: critical, high, medium, low
- **MITRE ATT&CK**: Technique mappings
- **Recommended Actions**: Step-by-step response guidance
- **Drilldown Searches**: Pre-built investigation queries

---

## Active Directory Notable Events

### Notable: Unauthorized Self-Service Admin Rights Grant

**Configuration**:
```
Title: CRITICAL - Self-Service Admin Grant - $TargetUserName$ added self to $privileged_group$
Description: User $TargetUserName$ added themselves to privileged group $privileged_group$ on $ComputerName$ at $time$.

This is an EXTREMELY HIGH confidence indicator of:
- Account compromise, OR
- Malicious insider activity

IMMEDIATE ACTION REQUIRED - This should NEVER occur during legitimate operations.

Account Details:
- User: $TargetUserName$
- Group: $privileged_group$
- Domain Controller: $ComputerName$
- Event ID: $EventCode$
- Source Logon ID: $SubjectLogonId$

Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1098

Recommended Actions:
1. IMMEDIATELY disable account $TargetUserName$:
   Disable-ADAccount -Identity $TargetUserName$

2. Remove from ALL privileged groups:
   Get-ADUser $TargetUserName$ -Properties MemberOf | Select -ExpandProperty MemberOf | ForEach {Remove-ADGroupMember -Identity $_ -Members $TargetUserName$ -Confirm:$false}

3. Revoke all active sessions:
   Revoke-AzureADUserAllRefreshToken -ObjectId $TargetUserName$@domain.com

4. Create CRITICAL incident ticket in JIRA
5. Notify SOC Lead and Incident Response Team immediately
6. Preserve all logs (DO NOT allow log rotation)
7. Begin full investigation of account activity
8. Check for:
   - Credential dumping
   - Lateral movement
   - Data exfiltration
   - Additional persistence mechanisms

Next Steps:
- Review all authentication logs for $TargetUserName$
- Check for unauthorized access to critical systems
- Determine initial compromise vector
- Full timeline analysis required

Drilldown Searches:
```

**Drilldown Search 1 - All Activity by User**:
```spl
index=windows EventCode IN (4624,4625,4672,4688,4768,4769)
| where TargetUserName="$TargetUserName$" OR Account_Name="$TargetUserName$"
| table _time, EventCode, ComputerName, IpAddress, LogonType, Process_Name
| sort _time
```

**Drilldown Search 2 - Group Modifications**:
```spl
index=windows EventCode IN (4728,4732,4756)
| where SubjectUserName="$TargetUserName$" OR TargetUserName="$TargetUserName$"
| table _time, EventCode, Group_Name, SubjectUserName, TargetUserName, ComputerName
```

**Drilldown Search 3 - Privileged Actions**:
```spl
index=windows EventCode=4672
| where SubjectUserName="$TargetUserName$"
| table _time, ComputerName, IpAddress, PrivilegeList
```

**Correlation Search Configuration**:
```
search = <SPL query from DET-AD-002>
cron_schedule = */5 * * * *
earliest_time = -10m
latest_time = now
actions = notable
action.notable.param.security_domain = access
action.notable.param.severity = critical
action.notable.param.urgency = critical
action.notable.param.rule_title = Unauthorized Self-Service Admin Rights Grant
action.notable.param.rule_description = <Description above>
action.notable.param.recommended_actions = <Actions above>
action.notable.param.nes_fields = TargetUserName, privileged_group, ComputerName, EventCode
action.notable.param.drilldown_name = View All Activity
action.notable.param.drilldown_search = <Drilldown Search 1>
action.notable.param.next_steps = Review user timeline, Investigate compromise vector, Create incident ticket
disabled = 0
```

---

### Notable: Kerberoasting Attack Detected

**Configuration**:
```
Title: Kerberoasting Attack - $Account_Name$ requested $unique_services$ service tickets
Description: Kerberoasting attack detected for account $Account_Name$ from $src_ip$.

Attack Indicators:
- Service tickets requested: $unique_services$
- Encryption type: RC4-HMAC (weak, crackable)
- Request pattern: Multiple SPNs in short timeframe
- Services targeted: $services$

This attack allows offline password cracking of service accounts.

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1558.003

Recommended Actions:
1. Disable account $Account_Name$ immediately:
   Disable-ADAccount -Identity $Account_Name$

2. Reset passwords for ALL service accounts requested:
   $services$ (each requires password reset)

3. Isolate source system $src_ip$

4. Investigate account for compromise indicators:
   - Unusual authentication patterns
   - Previous failed login attempts
   - Source of initial compromise

5. Implement mitigations:
   - Use long (25+ character) passwords for SPNs
   - Enable AES encryption for Kerberos
   - Implement gMSA for service accounts
   - Deploy Kerberos armoring

6. Check for offline cracking:
   - Monitor dark web for credential leaks
   - Assume passwords may be cracked
   - Force rotation for all SPNs

Drilldown Searches:
```

**Drilldown Search - Service Ticket Timeline**:
```spl
index=windows EventCode=4769
| where Account_Name="$Account_Name$"
| table _time, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

**Drilldown Search - All Kerberos Activity**:
```spl
index=windows EventCode IN (4768,4769,4770)
| where Account_Name="$Account_Name$"
| stats count by EventCode, Service_Name, Ticket_Encryption_Type
```

---

### Notable: Golden Ticket Attack Indicators

**Configuration**:
```
Title: CRITICAL - Golden Ticket Attack Indicators - $Account_Name$
Description: Multiple indicators of Golden Ticket attack detected for account $Account_Name$.

CRITICAL SEVERITY - This indicates potential FULL DOMAIN COMPROMISE.

Attack Indicators Detected:
- Abnormal ticket lifetime: $ticket_lifetime_hours$ hours (normal: <10)
- Encryption downgrade: RC4 for modern account
- Source: $Client_Address$
- TGT request anomalies detected

Golden Ticket Impact:
- Attacker can forge Kerberos tickets
- Can impersonate any user including Domain Admins
- Persistence mechanism surviving password changes
- Requires krbtgt account compromise

Severity: critical
Urgency: critical
Security Domain: access
MITRE ATT&CK: T1558.001

Recommended Actions:
1. IMMEDIATELY activate Incident Response Team
2. Notify CISO - This is a CRITICAL security incident
3. Assume FULL DOMAIN COMPROMISE

4. Isolate suspected compromised systems:
   - Source IP: $Client_Address$
   - Any systems accessed by $Account_Name$

5. DO NOT reset krbtgt password yet - preserve evidence first

6. Evidence Collection (CRITICAL):
   - Capture memory dumps from ALL domain controllers
   - Preserve ALL Kerberos logs
   - Export AD database for forensics
   - Document complete timeline

7. Investigate:
   - How was krbtgt hash obtained? (Usually via DCSync or NTDS.dit access)
   - What systems were accessed?
   - Was data exfiltrated?
   - Are there additional persistence mechanisms?

8. After evidence collection, reset krbtgt password TWICE:
   - First reset, wait 10 hours (max ticket lifetime)
   - Second reset
   - Use Microsoft script for safe reset

9. Full Active Directory security audit required
10. Consider complete domain rebuild if APT suspected

Next Steps:
- War room activation
- Forensic investigation (engage third party if needed)
- Determine scope of compromise
- Execute recovery plan
```

---

## Admin Abuse Notable Events

### Notable: Unauthorized Administrative Tool Execution

**Configuration**:
```
Title: Unauthorized Admin Tool - $tool_category$ - $User$ on $ComputerName$
Description: Unauthorized administrative or hacking tool detected on $ComputerName$.

Tool Details:
- Category: $tool_category$
- Process: $Image$
- User: $User$
- Command Line: $CommandLine$
- Parent Process: $ParentImage$
- File Hash (SHA256): $sha256$

Policy Violation:
This tool is NOT authorized per corporate security policy. Execution may indicate:
- Security incident / compromise
- Unauthorized penetration testing
- Malicious insider activity
- Policy violation requiring disciplinary action

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1588.002

Recommended Actions:
1. Isolate $ComputerName$ from network immediately:
   Via EDR console or physically disconnect

2. Disable user account $User$ pending investigation:
   Disable-ADAccount -Identity $User$

3. Preserve evidence (DO NOT reboot system):
   - Capture memory dump
   - Save running process list
   - Collect tool artifacts

4. Check tool authorization:
   - Review whitelist/approved security testing
   - Verify if legitimate security team activity
   - Check for approval documentation

5. If UNAUTHORIZED, investigate:
   - How was tool obtained? (download, USB, email?)
   - What actions did tool perform?
   - Was data exfiltrated or credentials stolen?
   - Check for additional tools/malware

6. Tool-Specific Actions:
   IF $tool_category$ = "Credential Dumping":
     - ASSUME all credentials on system compromised
     - Reset passwords for all admin accounts that accessed system
     - Review authentication logs for credential abuse
     - Check for Golden/Silver tickets

   IF $tool_category$ = "Remote Execution":
     - Identify all target systems
     - Check for lateral movement
     - Review processes created remotely

   IF $tool_category$ = "AD Enumeration":
     - Assume attack path reconnaissance
     - Review privileged accounts
     - Check for follow-on attacks

7. Scan for additional IOCs across environment
8. Create incident ticket and escalate

Drilldown Searches:
```

**Drilldown - Tool Execution Timeline**:
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where User="$User$" OR ComputerName="$ComputerName$"
| table _time, Image, CommandLine, ParentImage, Hashes
| sort _time
```

**Drilldown - Network Connections from Tool**:
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| where Image="$Image$" OR ProcessId="$ProcessId$"
| table _time, DestinationIp, DestinationPort, DestinationHostname
```

**Drilldown - File Hash Hunt**:
```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| rex field=Hashes "SHA256=(?<sha256_hunt>\w+)"
| where sha256_hunt="$sha256$"
| stats count by ComputerName, User
| eval description="Other systems where same tool hash detected"
```

---

## Network Lateral Movement Notable Events

### Notable: SMB Lateral Movement Detected

**Configuration**:
```
Title: SMB Lateral Movement - $source_host$ to $unique_targets$ targets
Description: SMB-based lateral movement detected from $source_host$ ($id.orig_h$) to $unique_targets$ different systems.

Network Activity:
- Source: $source_host$ / $id.orig_h$
- Targets: $unique_targets$ systems
- Target IPs: $targets$
- Shares accessed: $shares_accessed$
- Admin shares: Yes (C$, ADMIN$, IPC$)
- Timeframe: Multiple connections in short period

Pattern Analysis:
This behavior is consistent with:
- PsExec-style lateral movement
- Ransomware propagation
- Attacker reconnaissance and exploitation
- Automated lateral movement tools

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1021.002

Recommended Actions:
1. IMMEDIATELY isolate source $id.orig_h$:
   Block all outbound SMB (port 445) from source
   Isolate via EDR if available

2. Disable compromised account:
   Identify account used for SMB connections (check auth logs)
   Disable account immediately

3. Check all target systems for compromise:
   Target IPs: $targets$
   For each target:
     - Check for malware deployment
     - Review recent file modifications
     - Check for newly created services/scheduled tasks
     - Scan with AV/EDR

4. Investigate source system:
   - Identify malware or attacker tools
   - Determine initial compromise vector
   - Check for credential theft
   - Review all recent activity

5. Block SMB from source to targets:
   Firewall rules to prevent further spread

6. Evidence collection:
   - PCAP of SMB traffic (if available)
   - Memory dump from source system
   - Process list and network connections
   - File access logs from targets

7. Check for ransomware indicators:
   - File encryption attempts
   - Ransom notes
   - Mass file modifications

8. Escalate to Incident Response Team

Drilldown Searches:
```

**Drilldown - SMB Connection Timeline**:
```spl
index=corelight sourcetype=corelight_smb_mapping
| where id.orig_h="$id.orig_h$"
| table _time, id.resp_h, path, action
| sort _time
```

**Drilldown - Authentication for Source**:
```spl
index=windows EventCode=4624 Logon_Type=3
| where IpAddress="$id.orig_h$"
| table _time, ComputerName, TargetUserName, IpAddress, WorkstationName
```

**Drilldown - Target System Analysis**:
```spl
index=windows ComputerName IN ($targets$) EventCode IN (4688,7045,4698)
| table _time, ComputerName, EventCode, Process_Name, Service_Name, Task_Name
| eval activity=case(EventCode=4688,"Process Created",EventCode=7045,"Service Installed",EventCode=4698,"Scheduled Task Created")
```

---

## Policy Violation Notable Events

### Notable: Security Software Disabled

**Configuration**:
```
Title: Security Software Disabled - $service_stopped$ on $ComputerName$
Description: Security software was disabled on $ComputerName$ by $User$.

Security Software Disabled:
- Service: $service_stopped$
- System: $ComputerName$
- User: $User$
- Action: $action$
- Command: $CommandLine$ (if via command line)
- Method: $EventCode$

Policy Violation:
Security software must remain enabled at ALL times. Disabling security controls is:
- CRITICAL policy violation
- Potential indicator of malware/compromise
- Security incident requiring immediate response

Severity: high
Urgency: critical
Security Domain: endpoint
MITRE ATT&CK: T1562.001

Recommended Actions:
1. IMMEDIATELY re-enable security software:
   Via remote management console or GPO
   Verify service started successfully

2. If unable to re-enable remotely:
   - System may be compromised
   - Isolate from network immediately
   - Do NOT allow continued operation

3. Contact user $User$ to determine reason:
   - Was it intentional?
   - Who authorized it?
   - What was the justification?

4. If unauthorized, assume compromise:
   - Isolate system immediately
   - Preserve state (don't reboot yet)
   - Capture memory dump
   - Full malware scan after re-enabling AV

5. Review logs for period when protection was disabled:
   - Process creation events (EventCode 4688, Sysmon 1)
   - File creation/modification events
   - Network connections
   - Look for malware execution

6. Check for persistence mechanisms:
   - Scheduled tasks
   - Services
   - Registry autoruns
   - Startup folder items

7. If malware found:
   - Full incident response procedure
   - Eradication and recovery
   - Determine how security software was disabled
   - Implement tamper protection

8. If policy violation:
   - Document incident
   - User education/remediation
   - Disciplinary action if repeated

Drilldown Searches:
```

**Drilldown - Activity While Disabled**:
```spl
index=windows ComputerName="$ComputerName$"
    (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1)
    OR (sourcetype="WinEventLog:Security" EventCode=4688)
| table _time, User, Image, CommandLine, ParentImage
| sort _time
```

**Drilldown - File Creation While Disabled**:
```spl
index=windows ComputerName="$ComputerName$" sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| table _time, User, TargetFilename, Image
```

---

## Notable Event Response Workflow

### Standard Response Flow

```
1. Notable Generated in ES
   ↓
2. Auto-Create JIRA Ticket (via webhook)
   ↓
3. Analyst Reviews Notable
   ↓
4. Execute Drilldown Searches
   ↓
5. Follow Recommended Actions
   ↓
6. Update JIRA with Findings
   ↓
7. Escalate if Needed
   ↓
8. Document in JIRA
   ↓
9. Close Notable & JIRA Ticket
```

### Notable Event Priority Matrix

| Severity | Urgency | Response Time | Escalation |
|----------|---------|---------------|------------|
| Critical | Critical | <15 minutes | Immediate to IR Team |
| High | High | <1 hour | To SOC Lead if not resolved in 2h |
| Medium | Medium | <4 hours | To Team Lead if not resolved in 24h |
| Low | Low | <8 hours | Not required |

---

## Integration with JIRA

### Webhook Configuration

**Splunk Notable Event Action**:
```xml
<alert>
  <condition>
    <search>| makeresults | eval result="notable"</search>
  </condition>
  <action name="webhook">
    <param name="url">https://your-jira.atlassian.net/rest/api/3/issue</param>
    <param name="method">POST</param>
    <param name="headers">
      Authorization: Basic [base64_encoded_credentials]
      Content-Type: application/json
    </param>
    <param name="body">
    {
      "fields": {
        "project": {"key": "SOC"},
        "summary": "$result.rule_title$",
        "description": "$result.rule_description$",
        "issuetype": {"name": "Alert"},
        "customfield_10001": "$result.severity$",
        "customfield_10002": "$result.security_domain$",
        "customfield_10003": "Splunk ES",
        "customfield_10004": "$result.src$",
        "customfield_10005": "$result.user$",
        "labels": ["notable-event", "automated"]
      }
    }
    </param>
  </action>
</alert>
```

### JIRA Ticket Auto-Population

Notable events automatically populate JIRA with:
- **Summary**: Notable title
- **Description**: Full notable description with recommended actions
- **Severity**: From notable severity field
- **Detection Source**: "Splunk ES"
- **Affected Assets**: From notable events (user, src, dest)
- **IOCs**: From notable fields
- **Playbook Link**: Auto-attached based on category
- **Drilldown Links**: Direct links to Splunk searches

---

## Metrics & Tuning

### Notable Event Health Metrics

Track these metrics monthly:

```spl
index=notable
| stats count as total,
    count(eval(status="closed")) as closed,
    count(eval(status="in_progress")) as in_progress,
    count(eval(urgency="critical")) as critical,
    dc(rule_name) as unique_rules
by rule_name
| eval closure_rate=round(closed/total*100,2)
| sort - total
```

**Key Metrics**:
- Notable volume by rule
- True positive rate per rule
- Mean time to triage
- Mean time to close
- False positive rate
- Closure rate

### Tuning Process

**Monthly Review**:
1. Identify high-volume notables
2. Calculate true positive rate
3. Adjust thresholds for high FP rules
4. Update whitelists
5. Refine detection logic

**Quarterly Optimization**:
1. Full detection effectiveness review
2. Decommission low-value rules
3. Add detections for new threats
4. Update MITRE coverage

---

**Configuration Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
**Total Notable Configurations**: 15+
