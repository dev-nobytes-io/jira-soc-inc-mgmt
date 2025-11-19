# RE&CT Response Framework

## Overview

The RE&CT framework (Response, Eradication, & Containment Tree) provides structured response procedures for each phase of incident handling. This document maps specific RE&CT actions to use cases and provides step-by-step procedures.

**RE&CT Phases:**
- **RA1xxx** - Identification (gather data, confirm threat)
- **RA3xxx** - Containment (stop active exploitation, limit damage)
- **RA4xxx** - Eradication (remove attacker, close entry points)
- **RA5xxx** - Recovery (restore systems, verify baseline)
- **RA6xxx** - Lessons Learned (improve defenses, update detections)

---

## RA1xxx: Identification Phase

### RA1001: Collect Initial Evidence

**Trigger:** Any alert moved to Investigation  
**JIRA Integration:** Auto-create sub-task "Evidence Collection"

**Procedure:**

1. **Log Collection**
   ```
   • Windows Event Logs: 4624, 4625, 4728, 4688 (24h context)
   • Sysmon logs: Events 1, 3, 8, 10 (24h context)
   • Relevant application logs (context-dependent)
   ```

2. **System State Snapshot**
   ```
   FOR EACH AFFECTED HOST:
   • Running processes: tasklist /v
   • Network connections: netstat -anob
   • User sessions: quser
   • Scheduled tasks: tasklist /fo list /v | find "svchost"
   • Registry keys (suspicious locations):
     - HKCU\Software\Microsoft\Windows\Run
     - HKLM\Software\Microsoft\Windows\Run
   ```

3. **User Account Details**
   ```
   • Account properties: net user {username}
   • Group memberships: net user {username} | find "Group"
   • Last logon: Get-ADUser -Identity {user} -Properties LastLogonDate
   • Password age: net user {username} | find "Password"
   ```

4. **Preserve Evidence Chain**
   ```
   • Create evidence folder: C:\Evidence\{case-id}\
   • Hash all files: certutil -hashfile {file} SHA256
   • Document collection timestamp
   • Secure folder permissions: Remove external access
   • Link evidence files to JIRA sub-task
   ```

**Success Criteria:**
- [ ] All evidence collected and hashed
- [ ] Evidence linked to JIRA issue
- [ ] Chain of custody documented
- [ ] Timestamps verified

**JIRA Automation:** Evidence collection tickets auto-created with checklists per use case

---

### RA1002: Identify Affected Assets

**Trigger:** Identification phase in progress

**Procedure:**

1. **Scope Definition**
   ```
   PRIMARY ASSET (from alert):
   • Hostname
   • IP address
   • Owner/department
   • Criticality tier
   
   SECONDARY ASSETS:
   • Systems the account logged into (search 4624)
   • Systems the process executed on (search Event 1)
   • Shared resources accessed (search 5140, 5145)
   • Network destinations contacted (search network logs)
   ```

2. **Asset Documentation**
   ```
   Create JIRA custom field "Affected-Assets" with:
   • Asset name
   • Asset type (host, service, account, data)
   • Owner
   • Data classification
   • Criticality
   ```

3. **Scope Expansion Detection**
   ```
   Query for lateral movement:
   - Other hosts accessed by compromised account (4624)
   - Other accounts used from compromised host
   - Other data accessed in time window
   - RPC/WMI connections (port 135, 445, 5985)
   ```

**Success Criteria:**
- [ ] All directly affected assets identified
- [ ] Lateral movement scope documented
- [ ] Data exposure assessed
- [ ] Timeline of access confirmed

---

### RA1003: Determine Incident Type

**Trigger:** Initial evidence collected

**Procedure:**

1. **Threat Classification**
   ```
   Based on observed artifacts:
   
   [ ] EXTERNAL ATTACK
       Evidence: external IP, failed logins, exploit artifacts
       Action: Prepare containment (block IP)
       
   [ ] CREDENTIAL COMPROMISE
       Evidence: suspicious logons, admin actions, lateral movement
       Action: Prepare credential reset, account lockdown
       
   [ ] INSIDER THREAT
       Evidence: authorized user, unusual access, data exfiltration
       Action: Prepare monitoring, executive notification
       
   [ ] MALWARE/RAT
       Evidence: unauthorized process, C2 communication, persistence
       Action: Prepare eradication, host isolation
       
   [ ] MISCONFIGURATION
       Evidence: legitimate admin, expected action, change ticket present
       Action: Document and close
   ```

2. **Risk Assessment**
   ```
   [ ] Threat actor level: Script kiddie / APT / Nation-state
   [ ] Attack phase: Initial access / Persistence / Lateral / Exfiltration
   [ ] Capability: One-time / Sustained / Advanced
   [ ] Intent: Theft / Destruction / Espionage / Disruption
   ```

3. **JIRA Update**
   ```
   Set custom fields:
   • Verdict: True Positive / False Positive / Undetermined
   • Incident-Type: Attack / Malware / Insider / Misconfiguration
   • Estimated-Damage: None / Low / Medium / High
   ```

**Success Criteria:**
- [ ] Incident type clearly identified
- [ ] Risk level documented
- [ ] Escalation decision made
- [ ] Next phase actions clear

---

## RA3xxx: Containment Phase

### RA3101: Disable/Reset Compromised Credentials

**Trigger:** Credential compromise confirmed OR user compromise suspected

**Use Cases:** UC-001, UC-003, UC-004, UC-005

**Procedure:**

1. **Account Lockdown (Immediate)**
   ```
   FOR COMPROMISED USER ACCOUNT:
   • Disable account: Disable-ADUser -Identity {user}
   • Reset password to random 25-char string
   • Clear existing sessions: Get-ADSession | Remove-ADSession
   • Remove from all groups except "Domain Users"
   • Capture previous group membership before removal
   ```

2. **Escalation to Adjacent Accounts**
   ```
   FOR ACCOUNTS WITH PRIVILEGES:
   • Check if account used for:
     - Service accounts with credentials
     - Service running under account context
     - Scheduled tasks
   • Reset all service account passwords
   • Update service to use new credentials
   • Verify service restarts successfully
   ```

3. **Administrative Account Sweep**
   ```
   IF ADMIN ACCOUNT COMPROMISED:
   • Reset all admin account passwords
   • Audit domain admin group membership
   • Reset domain controller passwords
   • Force replication: repadmin /syncall /AdeP
   • Monitor for KRBTGT abuse: Invoke-Kerberoasting
   ```

4. **Verification**
   ```
   • Confirm account disabled in AD
   • Verify no RDP sessions exist
   • Check event logs for post-reset activity
   • Document timestamp and admin who reset
   ```

**JIRA Automation Trigger:**
```
IF Verdict = "True Positive" AND 
   (Use-Case IN [UC-001, UC-003, UC-004] OR 
    Field "Compromised-Account" populated)
THEN
   Create containment checklist with RA3101 tasks
   Notify AD team
   Set timer: 15-minute verification check
```

**Success Criteria:**
- [ ] Account disabled in AD
- [ ] Password reset completed
- [ ] Previous group memberships documented
- [ ] No post-reset activity detected

---

### RA3201: Terminate Suspicious Process

**Trigger:** Malware/unauthorized process execution confirmed

**Use Cases:** UC-002, UC-004, UC-005, UC-007

**Procedure:**

1. **Safe Termination**
   ```
   FOR CONFIRMED MALICIOUS PROCESS:
   • Document process details:
     - Process ID
     - Parent process
     - Command line
     - Creation timestamp
     - File path and hash
   
   • Check for child processes:
     wmic process list brief
   
   • Gracefully terminate (if safe):
     Stop-Process -Id {PID} -Force
   
   • If replicates or has children:
     taskkill /PID {PID} /T /F
   ```

2. **Prevent Restart/Replication**
   ```
   • Check Windows services for auto-start:
     Get-Service | Where-Object {$_.StartType -eq 'Auto'}
   
   • Disable any malicious services:
     Set-Service -Name {ServiceName} -StartupType Disabled
     Stop-Service -Name {ServiceName} -Force
   
   • Check scheduled tasks:
     schtasks /query /fo list /v | grep {process-name}
   
   • Remove malicious tasks:
     schtasks /delete /tn {TaskName} /f
   ```

3. **Verify Termination**
   ```
   • Confirm process no longer running:
     Get-Process -Name {process-name} 2>$null | 
     If-Object {$null -eq $_} {'TERMINATED'} Else {'STILL RUNNING'}
   
   • Check for persistence mechanisms:
     • Registry Run keys
     • Startup folder
     • Task Scheduler
   
   • Monitor for re-execution:
     Set-PSReadLineKeyHandler -Key Ctrl+R -Function {monitor}
   ```

**JIRA Automation:**
```
Create sub-task with automated:
  1. List running processes (pull via remote)
  2. Confirm suspicious process active
  3. Generate termination command
  4. Execute (with approval if critical)
  5. Verify termination
  6. Document in evidence sub-task
```

**Success Criteria:**
- [ ] Process terminated
- [ ] No child processes running
- [ ] Persistence mechanisms disabled
- [ ] No re-execution detected (30 min observation)

---

### RA3301: Block Malicious IP/Domain

**Trigger:** External attack source confirmed OR C2 communication detected

**Use Cases:** UC-003, UC-005, UC-006

**Procedure:**

1. **Immediate Blocking**
   ```
   FIREWALL RULE CREATION:
   • Rule name: {case-id}-{source-ip}
   • Direction: Inbound + Outbound
   • Action: Block
   • Protocol: Any
   • Source: {malicious-ip}
   • Destination: Any
   • Apply to: All segments
   ```

2. **DNS Blocking**
   ```
   INTERNAL DNS SERVERS:
   • Add DNS sinkhole rule:
     Zone: {malicious-domain}
     Target: 127.0.0.1 (internal sinkhole IP)
   
   • Verify resolution:
     nslookup {malicious-domain}
     → Should return sinkhole IP
   
   • Monitor DNS queries:
     Get-DnsClient -InterfaceAlias * | 
     Select-Object InterfaceAlias, ConnectionSpecificSuffix
   ```

3. **Proxy/Web Filter**
   ```
   IF using proxy/web filter:
   • Add domain to blocklist
   • Configure category block
   • Enable logging for attempts
   • Notify security for threat intel
   ```

4. **Verification**
   ```
   • Confirm rule deployed to firewalls
   • Test blocked connection (should fail):
     telnet {malicious-ip} 443
     → Should timeout/refuse
   
   • Monitor for bypass attempts:
     Look for:
     - Alternate ports
     - Proxy tunneling
     - DNS tunneling
   ```

**JIRA Automation:**
```
IF Alert contains "source_ip" field AND Use-Case = UC-003:
  1. Query threat intelligence
  2. Auto-generate firewall rule
  3. Request approval from network team (if prod)
  4. Deploy to firewall
  5. Verify block in place
  6. Document rule creation timestamp
```

**Success Criteria:**
- [ ] Firewall rule deployed
- [ ] DNS sinkhole configured
- [ ] Blocked connection test passed
- [ ] Monitoring alerts configured

---

## RA4xxx: Eradication Phase

### RA4101: Reset Compromised Credentials (Full Scope)

**Trigger:** Malware removal/eradication confirmed OR credential dump verified

**Use Cases:** UC-001, UC-004

**Procedure:**

1. **Immediate Credential Rotation**
   ```
   PHASE 1 - COMPROMISED ACCOUNTS:
   For each {compromised-account}:
   • Generate 25-character random password
   • Force password change: Set-ADAccountPassword
   • Set must-change-at-logon: Force-PasswordChange
   • Notify account owner via secure channel
   • Log all password changes
   ```

2. **Escalation Prevention**
   ```
   PHASE 2 - PRIVILEGE ABUSE PREVENTION:
   If account had admin access:
   • Reset ALL domain admin passwords
   • Reset LOCAL admin account on all servers
   • Reset domain controller machine accounts
   • Revoke PAM/PAW credentials
   • Clear Kerberos tickets: klist -li 0x3e7 purge
   ```

3. **Session Termination**
   ```
   PHASE 3 - ACTIVE SESSION CLEANUP:
   • Force all sessions to logoff:
     quser
     logoff {SessionID} /server:{server}
   
   • Or remotely via JIRA automation:
     For each affected_system:
       Get-WmiObject -Class Win32_LoggedInUser | 
       Where-Object {$_.Antecedent -match '{user}'} | 
       Remove-WmiObject
   ```

4. **Service Account Credentialing**
   ```
   PHASE 4 - SERVICE ACCOUNT RESET:
   For each service running under compromised account:
   • Note current service startup account
   • Generate new password
   • Update all services:
     Set-Service -Name {service} -Credential {new-cred}
   • Verify services restart:
     Restart-Service -Name {service} -Force
   • Monitor startup logs
   ```

**Success Criteria:**
- [ ] All passwords reset
- [ ] Sessions terminated
- [ ] Services restarted with new creds
- [ ] No authentication failures in logs

---

### RA4201: Remove Malware/Persistence

**Trigger:** Malware confirmed or persistence mechanisms detected

**Use Cases:** UC-002, UC-004, UC-007, UC-009, UC-010

**Procedure:**

1. **Malware Removal**
   ```
   AUTOMATED SCAN & REMOVAL:
   • Full system scan with antivirus:
     MpScan -ScanPath C:\ -ScanType 2 (Full scan)
   
   • Quarantine detected threats:
     Confirm in quarantine: Get-MpComputerStatus
   
   • Manual inspection of suspicious files:
     - Verify file hash against threat intel
     - Check digital signatures
     - Analyze with VirusTotal if needed
   
   • Remove quarantined items:
     Remove-MpPreference -ExclusionPath
   ```

2. **Persistence Mechanism Removal**
   ```
   CHECK PERSISTENCE LOCATIONS:
   
   REGISTRY:
   • HKCU\Software\Microsoft\Windows\Run
   • HKLM\Software\Microsoft\Windows\Run
   • HKCU\Software\Microsoft\Windows\Startup
   • HKLM\Software\Microsoft\Windows\Startup
   
   Remove with:
     Remove-ItemProperty -Path {registry-path} -Name {malware}
   
   SCHEDULED TASKS:
   • List all: schtasks /query /fo list /v
   • Remove: schtasks /delete /tn {TaskName} /f
   
   STARTUP FOLDER:
   • C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
   • C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
   
   WMI PERSISTENCE:
   • Query: Get-WmiObject -Namespace root\subscription -Class __EventFilter
   • Remove: Remove-WmiObject
   ```

3. **File System Cleanup**
   ```
   SUSPICIOUS FILE REMOVAL:
   • Locate suspicious files (from hash intel):
     Get-ChildItem -Path C:\ -Recurse -Filter {malware-name}
   
   • Backup for forensics:
     Copy-Item {file} -Destination C:\Evidence\{case-id}\ -Force
   
   • Remove malicious files:
     Remove-Item {file} -Force
   
   • Verify removal:
     Test-Path {file}
     → Should return $false
   ```

**JIRA Automation:**
```
Create "Eradication" sub-task with:
  1. Antivirus scan execution (automated)
  2. Quarantine confirmation
  3. Persistence check (automated search)
  4. File removal validation
  5. Evidence collection (files copied)
  6. Timestamp documentation
```

**Success Criteria:**
- [ ] No malware detected in scan
- [ ] Persistence mechanisms removed
- [ ] Files deleted and verified
- [ ] No unsigned processes running

---

### RA4401: Patch/Fix Exploitation Vector

**Trigger:** Exploitation or vulnerability confirmed

**Use Cases:** UC-002, UC-004, UC-007, UC-010

**Procedure:**

1. **Vulnerability Assessment**
   ```
   IDENTIFY ROOT CAUSE:
   • What was exploited?
     - Unpatched OS
     - Unpatched application
     - Misonfiguration
     - Weak credential
     - Insecure protocol
   
   • Document vulnerability:
     - CVE number (if applicable)
     - CVSS score
     - Remediation method
   ```

2. **Immediate Mitigation**
   ```
   IF UNPATCHED SYSTEM:
   • Prioritize patching:
     Priority 1: Domain controllers, Tier 1 servers
     Priority 2: Tier 2 servers, critical apps
     Priority 3: Tier 3, workstations
   
   • Test patch in non-prod:
     - Apply to test system
     - Run business application tests
     - Monitor event logs
     - Verify no new issues
   
   • Deploy to prod:
     - Schedule during maintenance window
     - Have rollback plan
     - Document deployment
     - Monitor post-patching
   
   • Windows Update command:
     Install-WindowsUpdate -AcceptAll
   ```

3. **Configuration Hardening**
   ```
   IF MISCONFIGURATION:
   • Identify correct configuration
   • Document current state
   • Apply hardening:
     - Disable unnecessary services
     - Restrict file permissions
     - Enable logging
     - Configure firewall rules
   
   • Verify change:
     - Check current configuration
     - Test application functionality
     - Monitor for issues
   ```

4. **Preventive Measures**
   ```
   ADD TO BASELINE HARDENING:
   • Update security baseline
   • Add to configuration management
   • Schedule regular reviews
   • Add detection for misconfiguration
   ```

**Success Criteria:**
- [ ] Vulnerability identified
- [ ] Patch/fix applied
- [ ] System tested
- [ ] Monitoring confirms remediation

---

## RA5xxx: Recovery Phase

### RA5001: Restore System from Backup

**Trigger:** Malware confirmed OR persistence extensively established

**Use Cases:** UC-002, UC-004, UC-007, UC-009, UC-010

**Procedure:**

1. **Backup Validation**
   ```
   IDENTIFY CLEAN BACKUP:
   • Review backup timeline relative to compromise
   • Select backup BEFORE first suspicious activity
   • Verify backup integrity:
     - Hash verification
     - Test restore in isolated environment
     - Confirm application functionality
   ```

2. **System Isolation**
   ```
   BEFORE RESTORE:
   • Disconnect system from network
   • Boot from recovery media if possible
   • Disable network interfaces in BIOS
   • Ensure no connectivity during restore
   ```

3. **Restoration Procedure**
   ```
   STEP-BY-STEP RESTORE:
   1. Boot from backup recovery media
   2. Authenticate with backup admin credentials
   3. Initiate restore:
      - Select backup point (pre-compromise)
      - Select full system restore
      - Verify restore options
   4. Wait for completion (may take hours)
   5. Verify integrity check passes
   6. Document restore timestamp
   ```

4. **Baseline Validation**
   ```
   POST-RESTORE CHECKS:
   • Verify system boots successfully
   • Check system time is correct
   • Verify all storage partitions mounted
   • Run filesystem integrity check
   • Check system event logs for errors
   • Verify no suspicious processes running
   ```

**Success Criteria:**
- [ ] Backup selected and verified
- [ ] Restore completed successfully
- [ ] All integrity checks passed
- [ ] No suspicious activity detected

---

### RA5101: Restore User Access

**Trigger:** Legitimate users locked out or access revoked during containment

**Use Cases:** UC-001, UC-003, UC-004

**Procedure:**

1. **Access Verification**
   ```
   BEFORE RESTORING ACCESS:
   • Confirm incident eradicated
   • Verify system is clean
   • Confirm user credentials reset
   • Approve restoration (manager sign-off)
   ```

2. **Credential Reset & Distribution**
   ```
   FOR EACH RESTORED USER:
   • Generate temporary password
   • Deliver via secure channel (not email):
     - SMS to phone number on file
     - In-person delivery
     - Verified phone call
   
   • User must change password at next login:
     Set-ADUser -PasswordNotRequired $false
     Set-ADUser -ChangePasswordAtLogon $true
   
   • Log distribution:
     - Timestamp
     - Admin who distributed
     - Delivery method
   ```

3. **Privilege Restoration**
   ```
   RESTORE APPROPRIATE GROUP MEMBERSHIPS:
   • Document original membership (from earlier evidence)
   • Restore groups:
     Add-ADGroupMember -Identity {GroupName} -Members {User}
   
   • Verify correct privileges:
     Get-ADGroupMember -Identity {GroupName}
   
   • NOT admin for regular users:
     - Add back to previous groups only
     - Minimum privilege principle
     - Manager approval for any elevation
   ```

4. **Access Monitoring**
   ```
   POST-RESTORATION MONITORING:
   • 30-day elevated monitoring:
     - All logons from user
     - All privilege use
     - File access (if sensitive data)
     - Network connections
   
   • Alert on suspicious activity:
     - Off-hours access
     - Unusual privilege use
     - Access to unfamiliar resources
   ```

**Success Criteria:**
- [ ] Credentials reset securely
- [ ] Group memberships restored
- [ ] User can authenticate
- [ ] Monitoring in place

---

## RA6xxx: Lessons Learned Phase

### RA6001: Incident Documentation

**Trigger:** Incident closure in JIRA

**JIRA Automation:** Auto-creates RA6001 sub-task with template

**Procedure:**

1. **Incident Timeline**
   ```
   DOCUMENT:
   • Initial compromise time (best estimate)
   • First detection time
   • Detection lag (hours between)
   
   TIMELINE TABLE:
   | Time | Event | Evidence |
   |------|-------|----------|
   | T+0 | Initial compromise | Log event ID |
   | T+X | Detection alert | Alert name, ticket |
   | T+Y | Containment started | Action timestamp |
   | T+Z | Eradication complete | Verification log |
   ```

2. **Root Cause Analysis**
   ```
   ANALYSIS TEMPLATE:
   
   WHAT HAPPENED:
   - Clear description of incident
   - Attack phases
   - Systems/data affected
   
   WHY IT HAPPENED:
   - Attack vector (phishing, exploit, etc.)
   - Vulnerability exploited
   - Configuration weakness
   - Control gap
   
   WHY WE DIDN'T STOP IT:
   - Detection gap
   - Visibility gap
   - Response gap
   - Process gap
   ```

3. **Impact Assessment**
   ```
   DOCUMENT:
   • Systems compromised
   • Data accessed/exfiltrated
   • Users affected
   • Business impact (downtime, etc.)
   • Regulatory impact (breach notification, etc.)
   
   QUANTIFY:
   • Dwell time (days attacker was present)
   • MTTR (mean time to respond)
   • MTTD (mean time to detect)
   • Detection lag (MTTD - actual compromise time)
   ```

**Success Criteria:**
- [ ] Timeline documented
- [ ] Root cause identified
- [ ] Impact quantified
- [ ] Documentation complete

---

### RA6002: Detection Improvement

**Trigger:** Lessons Learned phase, post-incident review

**Procedure:**

1. **Detection Gap Analysis**
   ```
   QUESTIONS TO ANSWER:
   • Did we detect the attack?
     - If YES: How quickly? Can we improve?
     - If NO: Why not? What detection would help?
   
   • What artifacts should have alerted?
     - Failed logins before success?
     - Unusual process execution?
     - Registry modifications?
     - File access patterns?
   
   • What detection do we have today?
     - Compare to incident artifacts
     - Identify gaps
   ```

2. **New Detection Implementation**
   ```
   FOR EACH DETECTION GAP:
   
   1. Design new analytic:
      - What to detect?
      - What data sources needed?
      - Query design
      - Threshold tuning
   
   2. Add to detection program:
      - Create ANALYTIC-0XX entry
      - Create UC-0XX use case
      - Map to MITRE ATT&CK
      - Add to runbook
   
   3. Deploy to production:
      - Test in dev environment
      - Validate on incident data
      - Deploy to Splunk
      - Configure alerting
   
   4. Baseline false positives:
      - Monitor for 2 weeks
      - Document baseline
      - Tune thresholds
   
   5. Document in runbook:
      - Detection methodology
      - Known false positives
      - Tuning guidance
   ```

**Example:**
```
INCIDENT: Credential dumping (UC-004)
WAS DETECTED: No
ARTIFACT: LSASS memory access by suspicious.exe

NEW DETECTION:
→ ANALYTIC-004 created
→ Monitor for Sysmon Event 10 (Process Access)
→ Alert on unauthorized LSASS access
→ Added to UC-004 runbook
→ Deployed production, baseline 2 weeks
```

**Success Criteria:**
- [ ] Detection gap identified
- [ ] New analytic designed
- [ ] Query validated on incident
- [ ] Deployed to production
- [ ] False positive baseline established

---

### RA6003: Control & Process Improvement

**Trigger:** Lessons Learned review, executive decision

**Procedure:**

1. **Identify Control Gaps**
   ```
   PREVENTIVE CONTROLS (Stop attacks):
   • What would have prevented compromise?
     - Patch (if exploit)
     - MFA (if credential)
     - Firewall rule (if network)
     - Email filter (if phishing)
   
   DETECTIVE CONTROLS (Detect faster):
   • What would detect sooner?
     - New analytics
     - Better baseline
     - Faster alerting
     - Correlation rules
   
   RESPONSIVE CONTROLS (Respond faster):
   • What would stop attacker faster?
     - Automation
     - Better process
     - Clearer escalation
     - Faster credentials reset
   ```

2. **Remediation Planning**
   ```
   CONTROL IMPLEMENTATION PLAN:
   
   Priority | Control | Type | Owner | Timeline | Cost |
   ---------|---------|------|-------|----------|------|
   1 | Network segmentation | Preventive | NetSec | Q2 2025 | $X |
   2 | EDR deployment | Detective | SysAdmin | Q1 2025 | $X |
   3 | MFA rollout | Preventive | IAM | Q1 2025 | $X |
   4 | Automation rule | Detective | SOC | Immediate | $0 |
   
   For each:
   • Owner assignment
   • Timeline and dependencies
   • Success metrics
   • Executive approval
   ```

3. **Process Documentation**
   ```
   UPDATE:
   • Incident Response Playbook
   • Change Control Process
   • Access Control Policy
   • Monitoring Configuration
   • Alert Response Procedures
   
   SHARE:
   • Team training session
   • Updated documentation repo
   • Stakeholder communication
   • Follow-up verification
   ```

**Success Criteria:**
- [ ] Control gaps documented
- [ ] Remediation plan created
- [ ] Owner assigned
- [ ] Timeline approved
- [ ] Implementation tracking started

---

## RE&CT Integration with JIRA

**Automatic RE&CT Phase Management:**

```
JIRA Board Column → RE&CT Phase

Triage Column → RA1xxx (Identification)
  Auto-create checklist:
  ☐ RA1001 - Collect evidence
  ☐ RA1002 - Identify assets
  ☐ RA1003 - Determine type

Investigation Column → RA1xxx Continued
  Continue RA1xxx tasks
  Determine escalation path

Containment Column → RA3xxx (Containment)
  Auto-create checklist:
  ☐ RA3101 - Reset credentials
  ☐ RA3201 - Terminate process
  ☐ RA3301 - Block IP

Eradication Column → RA4xxx (Eradication)
  Auto-create checklist:
  ☐ RA4101 - Full credential reset
  ☐ RA4201 - Remove persistence
  ☐ RA4401 - Patch vulnerability

Recovery Column → RA5xxx (Recovery)
  Auto-create checklist:
  ☐ RA5001 - Restore systems
  ☐ RA5101 - Restore access

Closed Column → RA6xxx (Lessons Learned)
  Auto-create checklist:
  ☐ RA6001 - Document incident
  ☐ RA6002 - Improve detection
  ☐ RA6003 - Improve controls
```

**Automation Template:**

```
When issue transitions to "Containment":
  1. Set RE&CT-Phase = "RA3xxx"
  2. Create sub-task checklist with RA3xxx actions
  3. Link to playbook document
  4. Add comment with next steps
  5. Notify containment team
```

---

## Validation Checklist

- [ ] All 7 RA phases documented
- [ ] Procedures step-by-step and actionable
- [ ] Commands copy-paste ready (where applicable)
- [ ] JIRA automation mapped to each action
- [ ] Success criteria defined
- [ ] Use case mappings accurate
- [ ] Team trained on procedures
- [ ] Templates created and shared
