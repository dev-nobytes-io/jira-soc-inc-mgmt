# Persistence Mechanism Detections

## Overview

Detections for common persistence techniques used by attackers to maintain access after initial compromise.

---

## DET-PERS-001: Scheduled Task Creation for Persistence

### Overview
- **Detection ID**: DET-PERS-001
- **MITRE ATT&CK**: T1053.005 (Scheduled Task)
- **Severity**: High
- **Data Sources**: Windows Security Logs, Sysmon

### Description

Detects creation of scheduled tasks used for persistence, including tasks that run at logon, regularly, or at system startup.

### SPL Query - Suspicious Scheduled Task Creation

```spl
index=windows (EventCode=4698 OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*schtasks.exe"))
| eval is_suspicious=if(
    match(TaskContent, "(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)")
    OR match(TaskContent, "(?i)(http|https|ftp)://")
    OR match(TaskContent, "(?i)(AppData|Temp|Public)")
    OR match(User_Context, "(?i)SYSTEM"),
    "true", "false"
)
| where is_suspicious="true"
| table _time, ComputerName, Task_Name, User_Context, TaskContent, SubjectUserName
| eval description="Suspicious scheduled task created for persistence"
```

### SPL Query - Hidden Scheduled Tasks

```spl
index=windows EventCode=4698
| rex field=TaskContent "<Hidden>(?<hidden_flag>[^<]+)</Hidden>"
| where hidden_flag="true"
| table _time, ComputerName, Task_Name, User_Context, TaskContent
| eval description="Hidden scheduled task created"
```

### SPL Query - Tasks Running as SYSTEM

```spl
index=windows EventCode=4698
| rex field=TaskContent "<UserId>(?<run_as_user>[^<]+)</UserId>"
| where run_as_user="NT AUTHORITY\\SYSTEM" OR run_as_user="SYSTEM"
| search NOT Task_Name IN ("Windows*", "Microsoft*")
| table _time, ComputerName, Task_Name, TaskContent, SubjectUserName
| eval description="Non-standard task running as SYSTEM"
```

### SPL Query - Command Line Task Creation

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where Image="*\\schtasks.exe"
| where match(CommandLine, "(?i)(/create|/sc|/tn)")
| eval is_suspicious=if(
    match(CommandLine, "(?i)(powershell|cmd|http|script|appdata)"),
    "true", "false"
)
| where is_suspicious="true"
| table _time, User, ComputerName, CommandLine, ParentImage
| eval description="Suspicious scheduled task creation via command line"
```

### Notable Event Configuration

```
Title: Suspicious Scheduled Task Created - $Task_Name$ on $ComputerName$
Description: Suspicious scheduled task detected:

Task Name: $Task_Name$
Computer: $ComputerName$
Created By: $SubjectUserName$
Run As: $User_Context$
Task Content: $TaskContent$

Indicators of malicious persistence:
- PowerShell/script execution
- HTTP/HTTPS URLs in task
- Runs from suspicious locations (AppData, Temp)
- Runs as SYSTEM
- Hidden task

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1053.005

Recommended Actions:
1. Review task details and command
2. Disable task immediately if malicious:
   schtasks /change /tn "$Task_Name$" /disable
3. Delete task:
   schtasks /delete /tn "$Task_Name$" /f
4. Investigate creating account $SubjectUserName$
5. Check for malware on $ComputerName$
6. Review all recent scheduled tasks on system
7. Scan for additional persistence mechanisms
```

### Response Actions

```powershell
# Disable suspicious task
schtasks /change /tn "TaskName" /disable

# Export task XML for analysis
schtasks /query /tn "TaskName" /xml > task.xml

# Delete task
schtasks /delete /tn "TaskName" /f

# List all tasks for review
schtasks /query /fo LIST /v
```

---

## DET-PERS-002: Registry Run Keys Persistence

### Overview
- **Detection ID**: DET-PERS-002
- **MITRE ATT&CK**: T1547.001 (Registry Run Keys)
- **Severity**: High
- **Data Sources**: Sysmon, Windows Security

### Description

Detects creation or modification of registry Run keys used to execute programs at user logon or system startup.

### SPL Query - Run Key Modifications

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject, "(?i)(\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run)")
| eval is_suspicious=if(
    match(Details, "(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32)")
    OR match(Details, "(?i)(AppData|Temp|Public|ProgramData)")
    OR match(Details, "(?i)(http|https|ftp)://"),
    "true", "false"
)
| where is_suspicious="true"
| table _time, ComputerName, User, TargetObject, Details, Image
| eval description="Suspicious registry run key modification"
```

### SPL Query - Startup Folder Modifications

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)(\\Start Menu\\Programs\\Startup|\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup)")
| table _time, ComputerName, User, TargetFilename, Image
| eval description="File created in Startup folder"
```

### SPL Query - Uncommon Run Key Values

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| where match(TargetObject, "(?i)\\CurrentVersion\\Run")
| rex field=TargetObject "\\Run(Once)?\\(?<key_name>[^\\]+)$"
| lookup common_run_keys.csv key_name OUTPUT expected
| where isnull(expected)
| table _time, ComputerName, User, key_name, TargetObject, Details
| eval description="Uncommon registry run key created"
```

### Notable Event Configuration

```
Title: Registry Run Key Persistence - $ComputerName$
Description: Registry run key modified for persistence:

Computer: $ComputerName$
User: $User$
Registry Key: $TargetObject$
Value: $Details$
Process: $Image$

This registry key executes at user logon or system startup.

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1547.001

Recommended Actions:
1. Review registry value details
2. If malicious, delete registry key:
   reg delete "$TargetObject$" /f
3. Check executable referenced in value
4. Investigate process that created key: $Image$
5. Scan system for malware
6. Review all Run keys on system:
   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### Response Commands

```powershell
# Query all Run keys
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Delete malicious key
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousKey"

# Export for analysis
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" run_keys.reg
```

---

## DET-PERS-003: Service Creation for Persistence

### Overview
- **Detection ID**: DET-PERS-003
- **MITRE ATT&CK**: T1543.003 (Windows Service)
- **Severity**: High
- **Data Sources**: Windows System Logs, Sysmon

### Description

Detects creation of Windows services used for persistence and privilege escalation.

### SPL Query - Suspicious Service Installation

```spl
index=windows (EventCode=7045 OR EventCode=4697)
| eval is_suspicious=if(
    match(Service_File_Name, "(?i)(powershell|cmd\.exe|wscript|cscript|rundll32)")
    OR match(Service_File_Name, "(?i)(AppData|Temp|Public|Users)")
    OR match(Service_Type, "user mode service")
    OR Service_Start_Type="auto start",
    "true", "false"
)
| where is_suspicious="true"
| table _time, ComputerName, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Account_Name
| eval description="Suspicious service installed"
```

### SPL Query - Service Creation via sc.exe

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where Image="*\\sc.exe"
| where match(CommandLine, "(?i)(create|config)")
| table _time, User, ComputerName, CommandLine, ParentImage
| eval description="Service created via sc.exe command"
```

### SPL Query - PowerShell Service Creation

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(New-Service|Set-Service.*-StartupType)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="Service created via PowerShell"
```

### Notable Event Configuration

```
Title: Suspicious Service Created - $Service_Name$ on $ComputerName$
Description: Suspicious Windows service installed:

Service Name: $Service_Name$
Computer: $ComputerName$
Binary Path: $Service_File_Name$
Start Type: $Service_Start_Type$
Run As: $Account_Name$

Indicators of malicious persistence:
- Runs from suspicious location
- Executes scripts or interpreters
- Auto-start configuration
- Runs as SYSTEM

Severity: high
Urgency: high
Security Domain: endpoint
MITRE ATT&CK: T1543.003

Recommended Actions:
1. Stop service immediately:
   sc stop "$Service_Name$"
2. Review service binary: $Service_File_Name$
3. If malicious, delete service:
   sc delete "$Service_Name$"
4. Investigate service binary for malware
5. Check for related persistence mechanisms
6. Review all recently created services
```

### Response Commands

```powershell
# List all services
Get-Service | Where-Object {$_.Status -eq "Running"}

# Get service details
Get-WmiObject Win32_Service | Where-Object {$_.Name -eq "ServiceName"} | Select *

# Stop and delete service
Stop-Service -Name "ServiceName" -Force
sc.exe delete "ServiceName"

# Query service configuration
sc qc "ServiceName"
```

---

## DET-PERS-004: WMI Event Subscription Persistence

### Overview
- **Detection ID**: DET-PERS-004
- **MITRE ATT&CK**: T1546.003 (WMI Event Subscription)
- **Severity**: High
- **Data Sources**: Sysmon, WMI-Activity Logs

### Description

Detects creation of WMI event subscriptions used for stealthy persistence.

### SPL Query - WMI Event Consumer Creation

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| where match(Consumer, "(?i)(powershell|cmd|wscript|cscript)")
| table _time, ComputerName, Consumer, ESS_Namespace
| eval description="Suspicious WMI event consumer created"
```

### SPL Query - Sysmon WMI Persistence

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=19 OR EventCode=20 OR EventCode=21)
| table _time, ComputerName, User, EventType, Operation, Consumer, Destination
| eval description="WMI persistence mechanism detected"
```

### SPL Query - PowerShell WMI Subscription

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where match(ScriptBlockText, "(?i)(Register-WmiEvent|Set-WmiInstance.*__EventFilter|__EventConsumer)")
| table _time, User, ComputerName, ScriptBlockText
| eval description="WMI subscription created via PowerShell"
```

### Notable Event Configuration

```
Title: WMI Event Subscription Persistence - $ComputerName$
Description: WMI event subscription created for persistence:

Computer: $ComputerName$
Consumer: $Consumer$
Event Type: $EventType$

WMI persistence is stealthy and commonly used by APTs.

Severity: high
Urgency: critical
Security Domain: endpoint
MITRE ATT&CK: T1546.003

Recommended Actions:
1. List all WMI subscriptions:
   Get-WMIObject -Namespace root\Subscription -Class __EventFilter
   Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer
2. Review consumer details for malicious activity
3. Delete malicious subscriptions:
   Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='FilterName'" | Remove-WmiObject
4. Full system malware scan
5. Check for additional persistence
```

### Response Commands

```powershell
# List all WMI event filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter

# List all consumers
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer
Get-WMIObject -Namespace root\Subscription -Class ActiveScriptEventConsumer

# List bindings (what triggers what)
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding

# Delete malicious subscription
$filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='EvilFilter'"
$consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='EvilConsumer'"
$binding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%EvilFilter%'"

$filter | Remove-WmiObject
$consumer | Remove-WmiObject
$binding | Remove-WmiObject
```

---

## DET-PERS-005: Account Creation for Persistence

### Overview
- **Detection ID**: DET-PERS-005
- **MITRE ATT&CK**: T1136.001 (Local Account), T1136.002 (Domain Account)
- **Severity**: High
- **Data Sources**: Windows Security Logs

### Description

Detects creation of local or domain accounts for persistent access.

### SPL Query - Local Account Creation

```spl
index=windows EventCode=4720
| search NOT SubjectUserName IN ("Administrator", "admin", "sccm*", "svc*")
| table _time, ComputerName, TargetUserName, SubjectUserName, TargetSid
| eval description="Local account created"
```

### SPL Query - Account Added to Administrators

```spl
index=windows EventCode=4732 OR EventCode=4728
| where Group_Name="Administrators" OR Group_Name="Domain Admins"
| table _time, ComputerName, Group_Name, TargetUserName, SubjectUserName
| eval description="Account added to privileged group"
```

### SPL Query - Hidden/Dollar Sign Accounts

```spl
index=windows EventCode=4720
| where match(TargetUserName, "\$")
| table _time, ComputerName, TargetUserName, SubjectUserName
| eval description="Hidden account created (ends with $)"
```

### Notable Event Configuration

```
Title: Suspicious Account Created - $TargetUserName$ on $ComputerName$
Description: User account created for potential persistence:

Account: $TargetUserName$
Computer: $ComputerName$
Created By: $SubjectUserName$

Suspicious indicators:
- Created outside normal onboarding
- Hidden account name ($ suffix)
- Immediately added to admin group

Severity: high
Urgency: high
Security Domain: access
MITRE ATT&CK: T1136.001, T1136.002

Recommended Actions:
1. Verify account creation with $SubjectUserName$
2. Check for legitimate business justification
3. If unauthorized, disable account:
   Disable-LocalUser -Name "$TargetUserName$"
   or
   Disable-ADAccount -Identity "$TargetUserName$"
4. Review account's group memberships
5. Check for any actions performed by account
6. Delete if malicious:
   Remove-LocalUser -Name "$TargetUserName$"
```

---

## DET-PERS-006: Webshell Detection

### Overview
- **Detection ID**: DET-PERS-006
- **MITRE ATT&CK**: T1505.003 (Web Shell)
- **Severity**: Critical
- **Data Sources**: IIS Logs, File System Events, Sysmon

### Description

Detects webshells deployed on web servers for persistent remote access.

### SPL Query - Suspicious Web Files Created

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| where match(TargetFilename, "(?i)(\.aspx|\.asp|\.php|\.jsp)")
| where match(TargetFilename, "(?i)(wwwroot|inetpub|htdocs|public_html)")
| eval is_suspicious=if(
    match(Image, "(?i)(cmd\.exe|powershell|w3wp\.exe)")
    OR match(User, "(?i)(IIS|NETWORK SERVICE|SYSTEM)"),
    "true", "false"
)
| where is_suspicious="true"
| table _time, ComputerName, TargetFilename, Image, User
| eval description="Suspicious web file created - possible webshell"
```

### SPL Query - Webshell Execution Patterns

```spl
index=iis
| eval is_webshell=if(
    match(cs_uri_stem, "(?i)(shell|cmd|eval|exec)")
    OR match(cs_uri_query, "(?i)(cmd|exec|eval|system)")
    OR match(cs_uri_query, "base64"),
    "true", "false"
)
| where is_webshell="true" AND sc_status=200
| stats count by cs_uri_stem, c_ip, cs_username
| eval description="Webshell execution detected"
```

### SPL Query - cmd.exe Spawned by Web Process

```spl
index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where ParentImage="*\\w3wp.exe" OR ParentImage="*\\apache*.exe" OR ParentImage="*\\nginx.exe"
| where match(Image, "(?i)(cmd\.exe|powershell\.exe|net\.exe|whoami\.exe)")
| table _time, ComputerName, Image, CommandLine, ParentImage, ParentCommandLine
| eval description="Suspicious process spawned by web server"
```

### Notable Event Configuration

```
Title: CRITICAL - Webshell Detected on $ComputerName$
Description: Webshell activity detected:

Server: $ComputerName$
File: $TargetFilename$
Process: $Image$
User: $User$

Webshells provide persistent remote access to web servers.

Severity: critical
Urgency: critical
Security Domain: endpoint
MITRE ATT&CK: T1505.003

Recommended Actions:
1. IMMEDIATE - Isolate web server from network
2. Review file contents: $TargetFilename$
3. Delete webshell file
4. Review IIS/Apache logs for access patterns
5. Identify how webshell was uploaded (vulnerability?)
6. Check for additional webshells
7. Full server compromise investigation
8. Patch web application vulnerability
9. Review all recent file modifications in webroot
```

---

## Summary - Persistence Detections

| Detection ID | Technique | MITRE | Severity | Stealth Level |
|--------------|-----------|-------|----------|---------------|
| DET-PERS-001 | Scheduled Tasks | T1053.005 | High | Medium |
| DET-PERS-002 | Registry Run Keys | T1547.001 | High | Low |
| DET-PERS-003 | Windows Services | T1543.003 | High | Medium |
| DET-PERS-004 | WMI Event Subscription | T1546.003 | High | High |
| DET-PERS-005 | Account Creation | T1136 | High | Low |
| DET-PERS-006 | Webshells | T1505.003 | Critical | Medium |

## Persistence Hunting Query

Hunt for multiple persistence mechanisms on a single system:

```spl
index=windows ComputerName="[target_host]"
    (EventCode=4698 OR EventCode=7045 OR EventCode=5861 OR EventCode=4720 OR EventCode=13)
| eval persistence_type=case(
    EventCode=4698, "Scheduled Task",
    EventCode=7045, "Service",
    EventCode=5861, "WMI Subscription",
    EventCode=4720, "Account Creation",
    EventCode=13 AND match(TargetObject, "Run"), "Registry Run Key",
    1=1, "Other"
)
| stats count by persistence_type, _time
| eval description="Multiple persistence mechanisms detected on single system"
```

---

**Detection Set Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: Detection Engineering Team
**Total Persistence Detections**: 6
