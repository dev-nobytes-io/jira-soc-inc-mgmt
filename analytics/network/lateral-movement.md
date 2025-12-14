# Network Lateral Movement Detections (Corelight/Zeek)

## Overview

Detections for lateral movement activity using network traffic analysis from Corelight/Zeek sensors.

---

## DET-NET-001: SMB Lateral Movement Detection

### Overview
- **Detection ID**: DET-NET-001
- **MITRE ATT&CK**: T1021.002 (SMB/Windows Admin Shares)
- **Severity**: High
- **Data Sources**: Corelight/Zeek SMB logs, NetFlow

### Description

Detects lateral movement via SMB, including PsExec-style execution and admin share access patterns indicative of lateral movement.

### SPL Query - Multiple SMB Connections

```spl
index=corelight sourcetype=corelight_smb_mapping
| stats dc(id.resp_h) as unique_targets, values(id.resp_h) as targets, values(path) as shares_accessed by id.orig_h, uid
| where unique_targets > 5
| lookup asset_info.csv ip as id.orig_h OUTPUT hostname as source_host, asset_type
| where asset_type!="admin_workstation"
| eval description="Potential SMB lateral movement - single source to multiple targets"
| table _time, source_host, id.orig_h, unique_targets, targets, shares_accessed
| sort - unique_targets
```

### SPL Query - Admin Share Access

```spl
index=corelight sourcetype=corelight_smb_mapping
| eval admin_share=if(match(path, "\\\\.*\\\\(C\$|ADMIN\$|IPC\$)"), "true", "false")
| where admin_share="true"
| stats count, dc(id.resp_h) as unique_targets, values(id.resp_h) as targets by id.orig_h, path
| where unique_targets > 3
| eval description="Multiple admin share accesses - likely lateral movement"
| table _time, id.orig_h, path, count, unique_targets, targets
```

### SPL Query - Rapid Sequential SMB

```spl
index=corelight sourcetype=corelight_smb_mapping
| streamstats time_window=5m dc(id.resp_h) as targets_5min by id.orig_h
| where targets_5min > 10
| stats count, values(id.resp_h) as targets, values(path) as shares by id.orig_h
| eval description="Rapid SMB access to multiple hosts - automated lateral movement"
| table _time, id.orig_h, count, targets, shares
```

### SPL Query - PsExec Detection (SMB Named Pipes)

```spl
index=corelight sourcetype=corelight_smb_files
| where match(name, "(?i)\\\\PIPE\\\\(psexesvc|remcom|paexec|csexecsvc)")
| stats count, values(id.resp_h) as targets, values(name) as pipes by id.orig_h, fuid
| eval description="PsExec-style named pipe detected - remote execution"
| table _time, id.orig_h, targets, pipes, count
```

### Notable Event Configuration

```
Title: SMB Lateral Movement Detected - $id.orig_h$ to $unique_targets$ targets
Description: Source $id.orig_h$ ($source_host$) accessed $unique_targets$ different systems via SMB within short timeframe.

Access pattern indicates lateral movement:
- Targets: $targets$
- Shares accessed: $shares_accessed$
- Admin shares: Yes
- Potential tool: PsExec or similar

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1021.002

Recommended Actions:
1. Isolate source system $id.orig_h$ immediately
2. Disable compromised account if identified
3. Investigate all target systems for compromise
4. Check for malware deployment or data theft
5. Review authentication logs for account used
6. Capture PCAP for forensic analysis
7. Escalate to Incident Response Team
```

### Corelight-Specific Detection - SMB Tree Connect

```spl
index=corelight sourcetype=corelight_dce_rpc
| where endpoint="svcctl"
| stats count, values(operation) as operations, dc(id.resp_h) as targets by id.orig_h
| where targets > 5
| eval description="Service Control Manager access to multiple hosts - remote service creation"
```

### Response Actions

**Immediate**:
1. Isolate source system
2. Disable account performing SMB access
3. Block SMB from source to targets

**Investigation**:
1. Identify account used
2. Review logs on all target systems
3. Check for malware deployment
4. Examine files transferred
5. Timeline of lateral movement

**Playbook**: [SMB Lateral Movement Response](../../playbooks/lateral-movement/smb-movement.md)

### SOAR Integration

```python
# SMB lateral movement response

# 1. Immediate containment
phantom.isolate_endpoint(ip=source_ip)

# 2. Block SMB traffic
phantom.add_firewall_rule(
    action="deny",
    protocol="tcp",
    port="445",
    source=source_ip,
    scope="enterprise"
)

# 3. Investigate targets
for target in targets:
    phantom.queue_endpoint_scan(ip=target)
    phantom.collect_logs(ip=target, log_type="security", hours=24)

# 4. Account investigation
phantom.get_smb_auth_events(source=source_ip, hours=24)

# 5. Create critical incident
phantom.create_incident(
    severity="high",
    title=f"SMB Lateral Movement: {source_ip} to {len(targets)} targets",
    category="Lateral Movement"
)
```

---

## DET-NET-002: RDP Lateral Movement Detection

### Overview
- **Detection ID**: DET-NET-002
- **MITRE ATT&CK**: T1021.001 (Remote Desktop Protocol)
- **Severity**: High
- **Data Sources**: Corelight/Zeek RDP logs, Windows Event Logs

### Description

Detects lateral movement via RDP connections to multiple systems, especially from non-admin workstations.

### SPL Query - Multiple RDP Connections

```spl
index=corelight sourcetype=corelight_rdp
| stats dc(id.resp_h) as unique_targets, values(id.resp_h) as targets by id.orig_h
| where unique_targets > 3
| lookup asset_info.csv ip as id.orig_h OUTPUT hostname as source_host, asset_type
| where asset_type!="jump_server" AND asset_type!="admin_workstation"
| eval description="Multiple RDP connections from single source - lateral movement"
| table _time, id.orig_h, source_host, unique_targets, targets
```

### SPL Query - RDP from Workstation to Workstation

```spl
index=corelight sourcetype=corelight_rdp
| lookup asset_info.csv ip as id.orig_h OUTPUT asset_type as source_type, hostname as source_host
| lookup asset_info.csv ip as id.resp_h OUTPUT asset_type as dest_type, hostname as dest_host
| where source_type="workstation" AND dest_type="workstation"
| stats count by id.orig_h, source_host, id.resp_h, dest_host
| eval description="Workstation-to-workstation RDP - unusual lateral movement"
| table _time, source_host, id.orig_h, dest_host, id.resp_h, count
```

### SPL Query - Rapid Sequential RDP

```spl
index=corelight sourcetype=corelight_rdp
| streamstats time_window=10m dc(id.resp_h) as rdp_targets_10min by id.orig_h
| where rdp_targets_10min > 5
| stats count, values(id.resp_h) as targets by id.orig_h
| eval description="Rapid RDP to multiple targets - automated lateral movement"
```

### SPL Query - Correlation with Failed Auth

```spl
index=corelight sourcetype=corelight_rdp
| join id.orig_h [
    search index=windows sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=10
    | stats count as failed_attempts by IpAddress
    | rename IpAddress as id.orig_h
]
| where failed_attempts > 5
| eval description="RDP connections with prior failed authentication - brute force + lateral movement"
```

### Notable Event Configuration

```
Title: RDP Lateral Movement - $source_host$ to $unique_targets$ systems
Description: RDP connections from $source_host$ ($id.orig_h$) to $unique_targets$ different systems:

Targets: $targets$
Source type: $source_type$
Pattern: Lateral movement via RDP

This behavior is consistent with attacker lateral movement across the network.

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1021.001

Recommended Actions:
1. Isolate source $id.orig_h$ immediately
2. Block RDP from source to targets
3. Disable account used for RDP connections
4. Check all target systems for compromise
5. Review RDP session logs for activity
6. Check for data staging or exfiltration
7. Escalate to IR Team
```

### Enhanced Detection - RDP with Anomalous Features

```spl
index=corelight sourcetype=corelight_rdp
| where security_protocol="HYBRID" OR ssl="F"
| stats count, values(id.resp_h) as targets by id.orig_h, security_protocol
| eval description="RDP without NLA or SSL - downgraded security for lateral movement"
```

### Response Actions

1. Isolate source system
2. Block RDP traffic
3. Disable account
4. Check all target systems
5. Review session activity

---

## DET-NET-003: WMI/DCOM Lateral Movement

### Overview
- **Detection ID**: DET-NET-003
- **MITRE ATT&CK**: T1047 (Windows Management Instrumentation), T1021.003 (DCOM)
- **Severity**: High
- **Data Sources**: Corelight DCE-RPC logs, Windows Event Logs

### Description

Detects lateral movement via WMI or DCOM, commonly used by advanced attackers and ransomware.

### SPL Query - WMI Lateral Movement (Network)

```spl
index=corelight sourcetype=corelight_dce_rpc
| where endpoint="IWbemServices"
| stats count, dc(id.resp_h) as unique_targets, values(id.resp_h) as targets, values(operation) as operations by id.orig_h
| where unique_targets > 3
| eval description="WMI access to multiple systems - lateral movement"
| table _time, id.orig_h, unique_targets, targets, operations, count
```

### SPL Query - WMI Process Creation (Endpoint)

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4688
| where Creator_Process_Name="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"
| stats count, dc(ComputerName) as affected_hosts, values(ComputerName) as hosts, values(Process_Name) as processes by Account_Name
| where affected_hosts > 3
| eval description="WMI-based remote process creation on multiple hosts"
```

### SPL Query - DCOM Lateral Movement

```spl
index=corelight sourcetype=corelight_dce_rpc
| where endpoint="IRemUnknown" OR endpoint="IObjectExporter"
| stats count, dc(id.resp_h) as unique_targets, values(id.resp_h) as targets by id.orig_h, endpoint
| where unique_targets > 5
| eval description="DCOM activity to multiple targets - lateral movement"
```

### SPL Query - MMC20.Application Abuse

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i)MMC20\\.Application")
| stats count, dc(ComputerName) as hosts by User, CommandLine
| where hosts > 3
| eval description="MMC20.Application DCOM lateral movement"
```

### Notable Event Configuration

```
Title: WMI/DCOM Lateral Movement - $id.orig_h$ to $unique_targets$ targets
Description: WMI or DCOM used for lateral movement from $id.orig_h$ to $unique_targets$ systems.

Method: $endpoint$
Operations: $operations$
Targets: $targets$

This technique is commonly used by ransomware and APT groups for lateral movement.

Severity: high
Urgency: critical
Security Domain: network
MITRE ATT&CK: T1047, T1021.003

Recommended Actions:
1. IMMEDIATELY isolate source $id.orig_h$
2. Disable account performing WMI/DCOM operations
3. Check all target systems for malware
4. Block WMI/DCOM from source to targets
5. Review processes created via WMI
6. Check for ransomware indicators
7. ESCALATE TO IR TEAM - HIGH PRIORITY
```

### Response Actions

**Critical Priority**:
1. Immediate isolation of source
2. Disable account
3. Check for ransomware on all targets
4. Block WMI/DCOM remotely
5. Emergency response activation

---

## DET-NET-004: Port Scanning from Internal Host

### Overview
- **Detection ID**: DET-NET-004
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Severity**: High
- **Data Sources**: Corelight/Zeek Connection logs

### Description

Detects internal port scanning activity indicative of network reconnaissance before lateral movement.

### SPL Query - High Port Volume

```spl
index=corelight sourcetype=corelight_conn
| where local_orig="T" AND local_resp="T"
| stats dc(id.resp_p) as unique_ports, dc(id.resp_h) as unique_hosts, values(id.resp_p) as ports by id.orig_h
| where unique_ports > 20 OR unique_hosts > 50
| eval description="Internal port scanning detected"
| table _time, id.orig_h, unique_hosts, unique_ports, ports
```

### SPL Query - Horizontal Scan

```spl
index=corelight sourcetype=corelight_conn
| where local_orig="T" AND local_resp="T"
| stats dc(id.resp_h) as unique_hosts, values(id.resp_h) as targets by id.orig_h, id.resp_p
| where unique_hosts > 20
| eval scan_type="Horizontal Scan"
| table _time, id.orig_h, id.resp_p, unique_hosts, targets, scan_type
```

### SPL Query - Vertical Scan

```spl
index=corelight sourcetype=corelight_conn
| where local_orig="T" AND local_resp="T"
| stats dc(id.resp_p) as unique_ports by id.orig_h, id.resp_h
| where unique_ports > 15
| eval scan_type="Vertical Scan"
| table _time, id.orig_h, id.resp_h, unique_ports, scan_type
```

### SPL Query - Failed Connection Patterns

```spl
index=corelight sourcetype=corelight_conn
| where conn_state="REJ" OR conn_state="S0"
| stats count as failed_conn, dc(id.resp_h) as unique_targets, dc(id.resp_p) as unique_ports by id.orig_h
| where failed_conn > 50 AND (unique_targets > 20 OR unique_ports > 15)
| eval description="Failed connection attempts - port scan"
```

### Notable Event Configuration

```
Title: Internal Port Scan Detected - $id.orig_h$
Description: Internal host $id.orig_h$ is conducting port scanning:

Scan statistics:
- Unique hosts scanned: $unique_hosts$
- Unique ports: $unique_ports$
- Scan type: $scan_type$
- Failed connections: $failed_conn$

This activity indicates reconnaissance before lateral movement or attack.

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1046

Recommended Actions:
1. Isolate $id.orig_h$ immediately
2. Investigate account logged into system
3. Check for malware/compromise
4. Block scanning activity
5. Review scan targets for vulnerability
6. Full system forensics
7. Escalate to IR Team
```

### Corelight-Specific - Scan Detection Log

```spl
index=corelight sourcetype=corelight_notice
| where note="Scan::Port_Scan" OR note="Scan::Address_Scan"
| table _time, src, dst, p, note, msg
| eval description="Corelight scan detection triggered"
```

### Response Actions

1. Isolate scanning host
2. Investigate compromise
3. Check malware presence
4. Review scan targets
5. Assess vulnerability exposure

---

## DET-NET-005: Internal DNS Tunneling

### Overview
- **Detection ID**: DET-NET-005
- **MITRE ATT&CK**: T1071.004 (DNS), T1048.003 (Exfiltration Over Alternative Protocol)
- **Severity**: High
- **Data Sources**: Corelight/Zeek DNS logs

### Description

Detects DNS tunneling used for C2 communication or data exfiltration during post-exploitation.

### SPL Query - High Query Volume

```spl
index=corelight sourcetype=corelight_dns
| stats count, dc(query) as unique_queries by id.orig_h, query
| where count > 100 OR unique_queries > 50
| eval description="High volume DNS queries - possible tunneling"
| table _time, id.orig_h, query, count, unique_queries
```

### SPL Query - Long DNS Query Names

```spl
index=corelight sourcetype=corelight_dns
| eval query_length=len(query)
| where query_length > 50
| stats count, avg(query_length) as avg_length, values(query) as queries by id.orig_h
| where count > 10
| eval description="Abnormally long DNS queries - possible tunneling"
```

### SPL Query - High Subdomain Entropy

```spl
index=corelight sourcetype=corelight_dns
| rex field=query "(?<subdomain>.+?)\.(?<domain>[^.]+\.[^.]+)$"
| eval subdomain_length=len(subdomain)
| where subdomain_length > 30
| stats count, values(query) as queries by id.orig_h, domain
| where count > 20
| eval description="High entropy subdomains - DNS tunneling"
```

### SPL Query - TXT Record Abuse

```spl
index=corelight sourcetype=corelight_dns
| where qtype_name="TXT"
| stats count, dc(query) as unique_queries, values(query) as queries by id.orig_h
| where count > 50
| eval description="High volume TXT queries - data exfiltration via DNS"
```

### Notable Event Configuration

```
Title: DNS Tunneling Detected - $id.orig_h$
Description: DNS tunneling activity detected from $id.orig_h$:

Indicators:
- Query count: $count$
- Unique queries: $unique_queries$
- Average query length: $avg_length$
- Domain: $domain$

Sample queries: $queries$

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1071.004, T1048.003

Recommended Actions:
1. Isolate $id.orig_h$ immediately
2. Block DNS queries to $domain$
3. Capture PCAP for analysis
4. Extract tunneled data if possible
5. Investigate for malware/C2
6. Check for data exfiltration
7. Escalate to IR Team
```

### Response Actions

1. Isolate host
2. Block suspicious domains
3. Capture network traffic
4. Analyze tunneled content
5. Check for C2 or exfiltration

---

## DET-NET-006: Abnormal Network Traffic Volume

### Overview
- **Detection ID**: DET-NET-006
- **MITRE ATT&CK**: T1041 (Exfiltration Over C2 Channel), T1020 (Automated Exfiltration)
- **Severity**: High
- **Data Sources**: Corelight/Zeek Connection logs, NetFlow

### Description

Detects abnormal network traffic volumes that may indicate data exfiltration or malware C2.

### SPL Query - Baseline Deviation

```spl
index=corelight sourcetype=corelight_conn
| stats sum(orig_bytes) as bytes_sent, sum(resp_bytes) as bytes_received by id.orig_h, id.resp_h
| eval total_bytes=bytes_sent + bytes_received
| eval MB_sent=round(bytes_sent/1024/1024,2)
| eval MB_received=round(bytes_received/1024/1024,2)
| where MB_sent > 500 OR MB_received > 500
| lookup baseline_traffic.csv id.orig_h OUTPUT avg_MB_sent, avg_MB_received
| eval sent_deviation=MB_sent/avg_MB_sent
| eval received_deviation=MB_received/avg_MB_received
| where sent_deviation > 5 OR received_deviation > 5
| eval description="Abnormal traffic volume - possible exfiltration"
| table _time, id.orig_h, id.resp_h, MB_sent, MB_received, sent_deviation, received_deviation
```

### SPL Query - Large Upload to External

```spl
index=corelight sourcetype=corelight_conn
| where local_orig="T" AND local_resp="F"
| stats sum(orig_bytes) as total_uploaded by id.orig_h, id.resp_h, id.resp_p
| eval MB_uploaded=round(total_uploaded/1024/1024,2)
| where MB_uploaded > 100
| lookup threat_intel.csv ip as id.resp_h OUTPUT threat_category, confidence
| eval description="Large upload to external IP - possible exfiltration"
| table _time, id.orig_h, id.resp_h, id.resp_p, MB_uploaded, threat_category, confidence
```

### Notable Event Configuration

```
Title: Abnormal Network Traffic Volume - $id.orig_h$ -> $id.resp_h$
Description: Abnormal network traffic detected from $id.orig_h$ to $id.resp_h$:

Traffic statistics:
- Data sent: $MB_sent$ MB
- Data received: $MB_received$ MB
- Deviation from baseline: $sent_deviation$x normal
- External destination: $local_resp$

This may indicate data exfiltration or malware C2 activity.

Severity: high
Urgency: high
Security Domain: network
MITRE ATT&CK: T1041, T1020

Recommended Actions:
1. Isolate $id.orig_h$ if not critical system
2. Block connection to $id.resp_h$
3. Capture PCAP of traffic
4. Identify what data was transferred
5. Check $id.resp_h$ reputation
6. Investigate source for compromise
7. Escalate if sensitive data suspected
```

---

## Summary - Network Lateral Movement Detections

| Detection ID | Technique | Protocol | Severity | Priority |
|--------------|-----------|----------|----------|----------|
| DET-NET-001 | SMB Lateral Movement | SMB | High | 1 |
| DET-NET-002 | RDP Lateral Movement | RDP | High | 1 |
| DET-NET-003 | WMI/DCOM | RPC | High | 1 |
| DET-NET-004 | Port Scanning | Multi | High | 2 |
| DET-NET-005 | DNS Tunneling | DNS | High | 2 |
| DET-NET-006 | Traffic Anomaly | Multi | High | 3 |

## Corelight-Specific Features

Corelight provides enhanced detection capabilities:

```spl
# Use Corelight's enriched logs
index=corelight sourcetype=corelight_*

# Corelight notice framework for built-in detections
sourcetype=corelight_notice

# Corelight encrypted traffic analysis
sourcetype=corelight_ssl

# Corelight file analysis
sourcetype=corelight_files
```

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Network Detection Team
