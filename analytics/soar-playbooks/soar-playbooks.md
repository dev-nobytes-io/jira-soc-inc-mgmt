# Splunk SOAR (Phantom) Playbook Examples

## Overview

This document provides complete Splunk SOAR playbook examples for automated incident response. These playbooks integrate with detection analytics to provide automated containment, investigation, and remediation.

## Playbook Index

1. [Privilege Escalation Response](#playbook-1-privilege-escalation-response)
2. [Kerberoasting Response](#playbook-2-kerberoasting-response)
3. [Unauthorized Tool Execution](#playbook-3-unauthorized-tool-execution)
4. [SMB Lateral Movement](#playbook-4-smb-lateral-movement)
5. [Golden Ticket Response](#playbook-5-golden-ticket-response-critical)
6. [Phishing Email Response](#playbook-6-phishing-email-response)
7. [Compromised Account Response](#playbook-7-compromised-account-response)

---

## Playbook 1: Privilege Escalation Response

### Overview

**Playbook Name**: `privilege_escalation_response`
**Trigger**: Notable event DET-AD-001 or DET-AD-002
**Severity**: Critical
**Automation Level**: Semi-automated (requires approval for account disable)

### Playbook Flow

```
[Trigger: Notable Event]
         ↓
[1. Gather Context]
         ↓
[2. Risk Assessment]
         ↓
[3. Check Change Management] → [Approved?] → Yes → [Document & Close]
         ↓ No
[4. User Notification]
         ↓
[5. Containment Decision] → [Auto-approve if self-grant]
         ↓
[6. Disable Account]
         ↓
[7. Remove from Groups]
         ↓
[8. Revoke Sessions]
         ↓
[9. Evidence Collection]
         ↓
[10. Create JIRA Incident]
         ↓
[11. Notify IR Team]
         ↓
[12. Investigation Tasks]
```

### Python Code Implementation

```python
"""
Splunk SOAR Playbook: Privilege Escalation Response
"""

def on_start(container):
    """
    Playbook entry point - triggered by notable event
    """
    phantom.debug('Privilege Escalation Response Playbook Started')

    # Extract notable event data
    subject_user = container['data'][0]['SubjectUserName']
    target_user = container['data'][0]['TargetUserName']
    group_name = container['data'][0]['privileged_group']
    computer_name = container['data'][0]['ComputerName']

    # Check if self-service grant (highest severity)
    if subject_user.lower() == target_user.lower():
        # Self-grant - auto-approve containment
        phantom.debug('Self-service grant detected - auto-containment approved')
        immediate_containment(container, target_user, group_name)
    else:
        # Third-party grant - need verification
        gather_context(container, subject_user, target_user, group_name)


def gather_context(container, subject_user, target_user, group_name):
    """
    Step 1: Gather contextual information about the privilege grant
    """
    phantom.debug('Gathering context for privilege escalation')

    # Get user details from AD
    phantom.act('get user attributes', {
        'username': target_user
    }, callback=user_details_callback)

    # Get recent activity for subject user
    phantom.act('run query', {
        'query': f'index=windows SubjectUserName="{subject_user}" | head 100',
        'command': 'search'
    }, callback=subject_activity_callback)

    # Check for active change management ticket
    check_change_management(container, subject_user, target_user, group_name)


def check_change_management(container, subject_user, target_user, group_name):
    """
    Step 3: Check if there's an approved change ticket
    """
    phantom.debug('Checking change management system')

    # Query ServiceNow for approved change
    phantom.act('run query', {
        'query': f'short_description CONTAINS "{target_user}" AND state=approved',
        'table': 'change_request'
    }, app_name='servicenow', callback=change_approval_callback)


def change_approval_callback(action, success, container, results, handle):
    """
    Callback: Process change management query results
    """
    if success and results[0]['data']:
        # Approved change found
        phantom.debug('Approved change ticket found')
        document_and_close(container, results[0]['data'][0]['number'])
    else:
        # No approval - proceed with containment
        phantom.debug('No approved change found - proceeding with containment')
        target_user = container['data'][0]['TargetUserName']
        group_name = container['data'][0]['privileged_group']

        # Send notification to SOC lead for approval
        request_containment_approval(container, target_user, group_name)


def request_containment_approval(container, target_user, group_name):
    """
    Step 5: Request approval for containment actions
    """
    phantom.debug('Requesting containment approval')

    # Create approval task
    phantom.prompt(
        user='soc_lead',
        message=f'''Unauthorized privilege escalation detected:
        User: {target_user}
        Group: {group_name}

        Approve immediate containment (disable account)?''',
        responses=['Yes', 'No'],
        callback=containment_decision_callback
    )


def containment_decision_callback(action, success, container, results, handle):
    """
    Callback: Process containment approval decision
    """
    response = results[0]['response']

    if response == 'Yes':
        phantom.debug('Containment approved')
        target_user = container['data'][0]['TargetUserName']
        group_name = container['data'][0]['privileged_group']
        immediate_containment(container, target_user, group_name)
    else:
        phantom.debug('Containment denied - manual investigation required')
        manual_investigation(container)


def immediate_containment(container, target_user, group_name):
    """
    Steps 6-8: Execute immediate containment actions
    """
    phantom.debug(f'Executing immediate containment for {target_user}')

    # Step 6: Disable AD account
    phantom.act('disable user', {
        'username': target_user
    }, app_name='active_directory', callback=disable_callback)

    # Step 7: Remove from ALL privileged groups
    phantom.act('run script', {
        'script_name': 'remove_from_all_groups',
        'parameters': f'username={target_user}'
    }, app_name='active_directory')

    # Step 8: Revoke all active sessions
    phantom.act('revoke user sessions', {
        'user': f'{target_user}@company.com'
    }, app_name='azure_ad')

    # Post-containment actions
    collect_evidence(container, target_user)
    create_incident_ticket(container, target_user, group_name)
    notify_ir_team(container, target_user, group_name)


def collect_evidence(container, target_user):
    """
    Step 9: Collect evidence for investigation
    """
    phantom.debug('Collecting evidence')

    # Collect authentication logs
    phantom.act('run query', {
        'query': f'''index=windows EventCode IN (4624,4625,4672,4768,4769)
                    TargetUserName="{target_user}" OR Account_Name="{target_user}"
                    | fields _time, EventCode, ComputerName, IpAddress, Process_Name''',
        'earliest_time': '-24h',
        'latest_time': 'now'
    }, app_name='splunk', callback=auth_logs_callback)

    # Collect group modification events
    phantom.act('run query', {
        'query': f'''index=windows EventCode IN (4728,4732,4756)
                    SubjectUserName="{target_user}" OR TargetUserName="{target_user}"
                    | fields _time, EventCode, Group_Name, SubjectUserName, TargetUserName''',
        'earliest_time': '-7d'
    }, app_name='splunk')

    # Check for privileged actions performed
    phantom.act('run query', {
        'query': f'''index=windows EventCode=4672 SubjectUserName="{target_user}"
                    | fields _time, ComputerName, IpAddress, PrivilegeList''',
        'earliest_time': '-24h'
    }, app_name='splunk')


def create_incident_ticket(container, target_user, group_name):
    """
    Step 10: Create JIRA incident ticket
    """
    phantom.debug('Creating JIRA incident ticket')

    summary = f'CRITICAL: Unauthorized Privilege Escalation - {target_user} added to {group_name}'

    description = f'''Automated Response to Privilege Escalation

User: {target_user}
Group: {group_name}
Detection: Automated via Splunk SOAR

Containment Actions Taken:
- Account disabled: Yes
- Removed from privileged groups: Yes
- Active sessions revoked: Yes
- Evidence collected: In progress

Incident Type: Privilege Escalation
Severity: Critical
Status: Under Investigation

Next Steps:
1. Review collected evidence
2. Determine root cause (compromise vs insider)
3. Full timeline analysis
4. Check for lateral movement
5. Assess impact and data access

Evidence artifacts attached to SOAR case.
'''

    phantom.act('create ticket', {
        'project_key': 'SOC',
        'summary': summary,
        'description': description,
        'issue_type': 'Incident',
        'priority': 'Critical',
        'labels': ['privilege-escalation', 'automated-response', 'critical']
    }, app_name='jira', callback=jira_ticket_callback)


def notify_ir_team(container, target_user, group_name):
    """
    Step 11: Notify Incident Response Team
    """
    phantom.debug('Notifying IR Team')

    # Send email to IR team
    phantom.act('send email', {
        'to': 'ir-team@company.com,soc-lead@company.com',
        'subject': f'CRITICAL: Privilege Escalation - {target_user}',
        'body': f'''CRITICAL SECURITY INCIDENT

Unauthorized privilege escalation detected and contained by SOAR:

User: {target_user}
Group: {group_name}
Time: {phantom.get_current_time()}

Automated Containment Completed:
✓ Account disabled
✓ Removed from privileged groups
✓ Sessions revoked
✓ Evidence collection in progress

JIRA Incident: [Created automatically]
SOAR Case ID: {container['id']}

IMMEDIATE ACTIONS REQUIRED:
1. Review evidence in SOAR case
2. Determine if account compromise or insider threat
3. Full investigation and timeline analysis
4. Assess potential impact

IR Team: Please review and take ownership.
'''
    }, app_name='smtp')

    # Send Slack notification
    phantom.act('send message', {
        'destination': '#soc-critical',
        'message': f'''🚨 CRITICAL INCIDENT - Automated Response Initiated

Privilege Escalation: {target_user} → {group_name}

Containment: ✓ Complete
JIRA: Creating...
Status: Awaiting IR Team review

SOAR Case: {container['id']}'''
    }, app_name='slack')

    # Page on-call engineer
    phantom.act('create incident', {
        'title': f'CRITICAL: Privilege Escalation - {target_user}',
        'description': 'Automated containment complete. Review required.',
        'urgency': 'high'
    }, app_name='pagerduty')


def investigation_tasks(container):
    """
    Step 12: Queue investigation tasks
    """
    phantom.debug('Creating investigation task list')

    target_user = container['data'][0]['TargetUserName']

    # Create task checklist in SOAR
    tasks = [
        'Review authentication timeline for compromise indicators',
        'Analyze source IPs and geolocations',
        'Check for credential dumping or malware',
        'Review all privileged actions performed',
        'Identify initial compromise vector',
        'Assess data access and exfiltration risk',
        'Determine if additional accounts compromised',
        'Check for persistence mechanisms',
        'Complete post-incident review',
        'Update detection rules based on findings'
    ]

    for task in tasks:
        phantom.add_note(container, task, note_type='task')

    # Set case status
    phantom.set_status(container, 'open')
    phantom.set_severity(container, 'high')


def document_and_close(container, change_ticket):
    """
    Close case for approved changes
    """
    phantom.debug('Approved change found - documenting and closing')

    phantom.add_note(container,
        f'Privilege grant approved via change ticket: {change_ticket}. No action required.',
        note_type='general')

    phantom.set_status(container, 'closed')
    phantom.close(container, 'false_positive')


# Playbook callback chain
phantom.register_action('on_start', on_start)
```

---

## Playbook 2: Kerberoasting Response

### Overview

**Playbook Name**: `kerberoasting_response`
**Trigger**: DET-KRB-001
**Severity**: High
**Automation Level**: Fully automated

### Playbook Actions

```python
"""
Splunk SOAR Playbook: Kerberoasting Response
"""

def on_start(container):
    """
    Automated response to Kerberoasting attack
    """
    phantom.debug('Kerberoasting Response Playbook Started')

    account_name = container['data'][0]['Account_Name']
    src_ip = container['data'][0]['src_ip']
    services = container['data'][0]['services'].split(',')

    # Immediate automated containment
    step_1_disable_account(container, account_name)
    step_2_isolate_source(container, src_ip)
    step_3_queue_spn_resets(container, services)
    step_4_investigate_source(container, src_ip)
    step_5_create_incident(container, account_name, services)


def step_1_disable_account(container, account_name):
    """
    Disable requesting account immediately
    """
    phantom.debug(f'Disabling account: {account_name}')

    phantom.act('disable user', {
        'username': account_name
    }, app_name='active_directory')

    phantom.add_note(container,
        f'Account {account_name} disabled automatically due to Kerberoasting attack')


def step_2_isolate_source(container, src_ip):
    """
    Isolate source system
    """
    phantom.debug(f'Isolating source: {src_ip}')

    # Isolate via EDR
    phantom.act('contain endpoint', {
        'ip_hostname': src_ip
    }, app_name='crowdstrike')

    # Block at firewall
    phantom.act('block ip', {
        'ip': src_ip,
        'direction': 'outbound',
        'duration': '24h'
    }, app_name='palo_alto')


def step_3_queue_spn_resets(container, services):
    """
    Create password reset tasks for all targeted SPNs
    """
    phantom.debug('Queuing SPN password resets')

    for service in services:
        # Extract account name from SPN
        if '/' in service:
            spn_account = service.split('/')[1].split(':')[0]

            # Create task for password reset
            phantom.add_task(container, {
                'title': f'Reset password for SPN: {spn_account}',
                'description': f'''Service account {spn_account} was targeted in Kerberoasting attack.

Password reset required:
1. Generate 25+ character random password
2. Reset in AD: Set-ADAccountPassword -Identity {spn_account}
3. Update service configuration with new password
4. Test service functionality
5. Document in JIRA ticket

Service targeted: {service}
Priority: HIGH''',
                'due_date': phantom.get_time(hours=4),
                'assigned_to': 'ad_admin_team'
            })


def step_4_investigate_source(container, src_ip):
    """
    Investigate source system for compromise
    """
    phantom.debug(f'Investigating source system: {src_ip}')

    # Get hostname from IP
    phantom.act('geolocate ip', {
        'ip': src_ip
    }, callback=ip_details_callback)

    # Collect system info
    phantom.act('get system info', {
        'ip_hostname': src_ip
    }, app_name='crowdstrike')

    # Get running processes
    phantom.act('list processes', {
        'ip_hostname': src_ip
    }, app_name='crowdstrike', callback=process_analysis_callback)

    # Scan for Kerberoasting tools
    phantom.act('run query', {
        'query': f'''index=windows ComputerName="{src_ip}" OR src_ip="{src_ip}"
                    sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
                    (Image="*rubeus*" OR Image="*kerberoast*" OR CommandLine="*GetUserSPNs*")
                    | fields _time, User, Image, CommandLine''',
        'earliest_time': '-24h'
    }, app_name='splunk', callback=tool_detection_callback)


def process_analysis_callback(action, success, container, results, handle):
    """
    Analyze running processes for Kerberoasting tools
    """
    if success:
        processes = results[0]['data']

        suspicious_processes = []
        for process in processes:
            process_name = process.get('process_name', '').lower()

            # Check for known Kerberoasting tools
            if any(tool in process_name for tool in ['rubeus', 'mimikatz', 'powershell', 'kekeo']):
                suspicious_processes.append(process)

                # Kill suspicious process
                phantom.act('kill process', {
                    'ip_hostname': container['data'][0]['src_ip'],
                    'pid': process['pid']
                }, app_name='crowdstrike')

        if suspicious_processes:
            phantom.add_note(container,
                f'Suspicious processes detected and terminated: {suspicious_processes}',
                note_type='general')


def step_5_create_incident(container, account_name, services):
    """
    Create JIRA incident ticket
    """
    summary = f'Kerberoasting Attack - {account_name} - {len(services)} SPNs targeted'

    description = f'''Kerberoasting Attack Detected and Contained

Attacking Account: {account_name}
Source IP: {container['data'][0]['src_ip']}
Services Targeted: {len(services)}
Service List: {", ".join(services)}

Automated Containment Completed:
✓ Attacking account disabled
✓ Source system isolated
✓ SPN password reset tasks created

Attack Method:
- Multiple service ticket requests (TGS-REQ)
- RC4 encryption (weak, crackable offline)
- Requests for service accounts with SPNs

Risk:
Service account passwords may be cracked offline. Assume compromise pending password resets.

Response Actions Required:
1. Reset all targeted SPN passwords (tasks created)
2. Investigate source system for malware
3. Determine initial compromise vector
4. Implement SPN hardening (long passwords, gMSA)

Evidence collected in SOAR case.
'''

    phantom.act('create ticket', {
        'project_key': 'SOC',
        'summary': summary,
        'description': description,
        'issue_type': 'Incident',
        'priority': 'High',
        'labels': ['kerberoasting', 'automated-response']
    }, app_name='jira')
```

---

## Playbook 3: Unauthorized Tool Execution

### Playbook Flow

```python
"""
Splunk SOAR Playbook: Unauthorized Tool Execution Response
"""

def on_start(container):
    """
    Response to unauthorized admin/hacking tool execution
    """
    tool_category = container['data'][0]['tool_category']
    computer_name = container['data'][0]['ComputerName']
    user = container['data'][0]['User']
    sha256 = container['data'][0]['sha256']

    # Check authorization
    if check_whitelist(user, sha256):
        document_approved_usage(container)
    else:
        # Unauthorized - immediate response
        immediate_containment(container, computer_name, user)
        tool_specific_response(container, tool_category)
        evidence_collection(container, computer_name, sha256)
        create_incident(container, tool_category, user)


def immediate_containment(container, computer_name, user):
    """
    Immediate containment actions
    """
    # Isolate endpoint
    phantom.act('contain endpoint', {
        'ip_hostname': computer_name
    }, app_name='crowdstrike')

    # Disable user account
    phantom.act('disable user', {
        'username': user
    }, app_name='active_directory')

    # Kill tool process if still running
    tool_image = container['data'][0]['Image']
    phantom.act('terminate process', {
        'ip_hostname': computer_name,
        'process_name': tool_image
    }, app_name='crowdstrike')


def tool_specific_response(container, tool_category):
    """
    Tool category-specific response actions
    """
    computer_name = container['data'][0]['ComputerName']

    if tool_category == "Credential Dumping":
        # CRITICAL - Assume all credentials compromised
        phantom.set_severity(container, 'high')

        # Create tasks for password resets
        phantom.add_task(container, {
            'title': 'Reset ALL admin passwords that accessed this system',
            'description': '''Credential dumping tool detected. Assume all credentials on system compromised.

Actions required:
1. Identify all admin accounts that logged into this system (last 30 days)
2. Reset passwords for ALL identified accounts
3. Reset local admin password (LAPS)
4. Check for Golden/Silver ticket indicators
5. Review authentication logs for credential abuse

Priority: CRITICAL''',
            'due_date': phantom.get_time(hours=2)
        })

    elif tool_category == "Remote Execution":
        # Lateral movement likely
        phantom.add_task(container, {
            'title': 'Investigate lateral movement',
            'description': f'''Remote execution tool detected. Check for lateral movement:

1. Identify all target systems from {computer_name}
2. Review SMB/RDP/WMI connections
3. Check processes created on target systems
4. Scan targets for malware
5. Timeline analysis

Tool: {container['data'][0]['Image']}''',
            'due_date': phantom.get_time(hours=4)
        })

    elif tool_category == "AD Enumeration":
        # Reconnaissance before attack
        phantom.add_task(container, {
            'title': 'Review privileged accounts and attack paths',
            'description': '''AD enumeration tool detected. Attacker has mapped environment.

Actions:
1. Review most privileged accounts
2. Harden attack paths
3. Check for follow-on attacks (Kerberoasting, etc.)
4. Enhanced monitoring for targeted accounts
5. Review AD security posture

Priority: HIGH''',
            'due_date': phantom.get_time(hours=8)
        })


def evidence_collection(container, computer_name, sha256):
    """
    Collect forensic evidence
    """
    # Memory dump (critical - before reboot)
    phantom.act('get memory dump', {
        'ip_hostname': computer_name
    }, app_name='crowdstrike')

    # Process list
    phantom.act('list processes', {
        'ip_hostname': computer_name
    }, app_name='crowdstrike')

    # Network connections
    phantom.act('list connections', {
        'ip_hostname': computer_name
    }, app_name='crowdstrike')

    # File hash hunt across environment
    phantom.act('hunt file', {
        'hash': sha256
    }, app_name='crowdstrike', callback=hash_hunt_callback)

    # Get file details
    phantom.act('get file', {
        'ip_hostname': computer_name,
        'file_path': container['data'][0]['Image']
    }, app_name='crowdstrike')


def hash_hunt_callback(action, success, container, results, handle):
    """
    Process hash hunt results - check if tool on other systems
    """
    if success and results[0]['data']:
        affected_systems = results[0]['data']

        if len(affected_systems) > 1:
            # Tool found on multiple systems - widespread issue
            phantom.set_severity(container, 'high')

            phantom.add_note(container,
                f'''ALERT: Tool hash found on {len(affected_systems)} systems:
{affected_systems}

This indicates widespread deployment. Consider:
1. Automated deployment mechanism
2. Worm-like propagation
3. Coordinated attack
4. All systems require investigation''',
                note_type='general')

            # Create tasks for each system
            for system in affected_systems:
                if system != container['data'][0]['ComputerName']:
                    phantom.add_task(container, {
                        'title': f'Investigate {system} for unauthorized tool',
                        'description': f'Same tool hash found on {system}. Investigate and contain.',
                        'due_date': phantom.get_time(hours=4)
                    })
```

---

## Playbook 5: Golden Ticket Response (CRITICAL)

### Overview

**Playbook Name**: `golden_ticket_response_critical`
**Trigger**: DET-KRB-002
**Severity**: Critical
**Automation Level**: Hybrid (automated evidence collection, manual approval for domain-wide actions)

### Playbook Code

```python
"""
Splunk SOAR Playbook: Golden Ticket Response - CRITICAL
Domain Compromise Scenario
"""

def on_start(container):
    """
    CRITICAL INCIDENT: Possible Golden Ticket attack
    This indicates FULL DOMAIN COMPROMISE
    """
    phantom.debug('CRITICAL: Golden Ticket Response Initiated')

    # Immediate critical notifications
    critical_notifications(container)

    # Evidence preservation (BEFORE any remediation)
    preserve_evidence(container)

    # Containment (limited to affected systems only)
    contain_affected_systems(container)

    # Create war room
    activate_war_room(container)

    # Queue investigation tasks
    investigation_checklist(container)


def critical_notifications(container):
    """
    IMMEDIATE notifications to all stakeholders
    """
    account_name = container['data'][0]['Account_Name']
    client_address = container['data'][0]['Client_Address']

    # Page CISO, IR Lead, SOC Lead
    phantom.act('create incident', {
        'title': 'CRITICAL: Golden Ticket Attack - Domain Compromise',
        'description': f'''CRITICAL SECURITY INCIDENT

Golden Ticket attack detected. This indicates FULL ACTIVE DIRECTORY COMPROMISE.

Account: {account_name}
Source: {client_address}

IMMEDIATE RESPONSE REQUIRED
War room activation initiated.

DO NOT take any remediation actions until evidence is preserved.''',
        'urgency': 'high',
        'escalation_policy': 'ciso_escalation'
    }, app_name='pagerduty')

    # Email to executive team
    phantom.act('send email', {
        'to': 'ciso@company.com,ceo@company.com,ir-lead@company.com',
        'cc': 'legal@company.com',
        'subject': 'CRITICAL INCIDENT: Active Directory Compromise',
        'body': f'''CRITICAL SECURITY INCIDENT - IMMEDIATE ATTENTION REQUIRED

A Golden Ticket attack has been detected, indicating compromise of the Active Directory krbtgt account.

IMPACT: Full domain compromise - attacker can impersonate any user
SEVERITY: Critical
STATUS: Under investigation

Automated response initiated:
- Evidence preservation in progress
- War room activated
- Incident Response Team paged

Next briefing: 30 minutes

IR Team Lead: Please join war room immediately.
CISO: Executive briefing required.

SOAR Case ID: {container['id']}'''
    }, app_name='smtp')

    # Slack critical alert
    phantom.act('send message', {
        'destination': '#security-leadership',
        'message': f'''@channel 🚨 CRITICAL INCIDENT 🚨

Golden Ticket Attack Detected
**Domain Compromise Scenario**

Account: {account_name}
Source: {client_address}

War Room: #incident-{container['id']}
Status: Evidence preservation in progress

All hands on deck. Join war room immediately.'''
    }, app_name='slack')


def preserve_evidence(container):
    """
    CRITICAL: Preserve evidence BEFORE any remediation
    Evidence collection is highest priority
    """
    phantom.debug('Preserving critical evidence')

    # Capture memory from ALL domain controllers
    dcs = get_domain_controllers()

    for dc in dcs:
        phantom.act('get memory dump', {
            'ip_hostname': dc,
            'priority': 'critical'
        }, app_name='crowdstrike')

        phantom.add_note(container,
            f'Memory dump queued for DC: {dc}',
            note_type='task')

    # Export AD database for forensics
    phantom.add_task(container, {
        'title': 'Export Active Directory database for forensic analysis',
        'description': '''Export ntds.dit from all domain controllers:

1. Use ntdsutil or Volume Shadow Copy
2. Preserve offline copy
3. Hash and document chain of custody
4. Store in secure forensic repository

DO NOT MODIFY AD until exports complete.

Priority: CRITICAL - Complete before any remediation''',
        'due_date': phantom.get_time(hours=1),
        'assigned_to': 'forensics_team'
    })

    # Preserve ALL Kerberos logs
    phantom.act('run query', {
        'query': '''index=windows sourcetype="WinEventLog:Security"
                    (EventCode=4768 OR EventCode=4769 OR EventCode=4770 OR EventCode=4771)
                    | collect index=forensics_hold marker="golden_ticket_investigation"''',
        'earliest_time': '-30d'
    }, app_name='splunk')

    # Document timeline
    create_timeline(container)


def contain_affected_systems(container):
    """
    Contain ONLY confirmed affected systems
    Do NOT take domain-wide action yet
    """
    client_address = container['data'][0]['Client_Address']

    # Isolate source system only
    phantom.act('contain endpoint', {
        'ip_hostname': client_address
    }, app_name='crowdstrike')

    phantom.add_note(container,
        f'Source system {client_address} isolated. NO domain-wide actions taken yet.',
        note_type='general')

    # DO NOT reset krbtgt password yet - requires careful planning


def investigation_checklist(container):
    """
    Create comprehensive investigation task list
    """
    tasks = [
        {
            'title': 'Determine krbtgt compromise vector',
            'description': '''Identify HOW krbtgt hash was obtained:

Possible vectors:
1. DCSync attack (Event 4662 with specific GUIDs)
2. ntds.dit access/theft
3. Domain controller compromise
4. Volume Shadow Copy access
5. Credential dumping from DC

Review logs and determine method.

Priority: CRITICAL''',
            'due_date': phantom.get_time(hours=2)
        },
        {
            'title': 'Identify ALL compromised systems',
            'description': '''Map full scope of compromise:

1. Systems accessed by attacker
2. Accounts used
3. Data accessed/exfiltrated
4. Persistence mechanisms deployed
5. Malware distribution

Complete environment assessment required.''',
            'due_date': phantom.get_time(hours=4)
        },
        {
            'title': 'Check for additional persistence mechanisms',
            'description': '''Beyond Golden Ticket, look for:

- Backdoor accounts
- Malicious GPOs
- Scheduled tasks
- Services
- AdminSDHolder modification
- DCShadow
- Skeleton Key malware

Full AD security audit required.''',
            'due_date': phantom.get_time(hours=6)
        },
        {
            'title': 'Plan krbtgt password reset procedure',
            'description': '''CRITICAL: krbtgt reset requires careful planning:

1. Reset krbtgt password
2. Wait 10 hours (max ticket lifetime)
3. Reset AGAIN (second reset)

**Requirements:**
- All DCs online and replicating
- No production outages during reset
- Change control approval
- Tested rollback plan

Do NOT execute until approved by IR Lead and CISO.

Reference: Microsoft krbtgt reset script
https://github.com/microsoft/New-KrbtgtKeys.ps1''',
            'due_date': phantom.get_time(hours=24),
            'assigned_to': 'ir_lead'
        },
        {
            'title': 'Assess data exfiltration',
            'description': '''Determine what data was accessed:

1. Review file access logs
2. Check network traffic for large transfers
3. Review email sending patterns
4. Check cloud storage access
5. Database access logs

Data breach notification may be required.''',
            'due_date': phantom.get_time(hours=8)
        },
        {
            'title': 'Engage third-party forensics (if needed)',
            'description': '''Consider engaging external IR firm:

Criteria for external engagement:
- APT suspected
- Insufficient internal resources
- Legal/compliance requirements
- Board/insurance requirements

Discuss with CISO and Legal.''',
            'due_date': phantom.get_time(hours=4),
            'assigned_to': 'ciso'
        }
    ]

    for task in tasks:
        phantom.add_task(container, task)


def activate_war_room(container):
    """
    Create dedicated incident war room
    """
    # Create Slack channel
    phantom.act('create channel', {
        'name': f'incident-{container["id"]}-golden-ticket',
        'purpose': 'Golden Ticket attack response war room',
        'is_private': False
    }, app_name='slack')

    # Invite key personnel
    phantom.act('invite to channel', {
        'channel': f'incident-{container["id"]}-golden-ticket',
        'users': 'ciso,ir-lead,soc-lead,forensics-lead'
    }, app_name='slack')

    # Post initial briefing
    phantom.act('send message', {
        'destination': f'#incident-{container["id"]}-golden-ticket',
        'message': '''🚨 GOLDEN TICKET ATTACK WAR ROOM 🚨

CRITICAL INCIDENT: Active Directory Domain Compromise

Status: Evidence preservation in progress
Next Update: 30 minutes

Tasks assigned in SOAR case. Please check assignments.

**DO NOT** take remediation actions without IR Lead approval.
**PRIORITY**: Evidence preservation and scope assessment.

War room active 24/7 until incident resolved.'''
    }, app_name='slack')


# Helper functions
def get_domain_controllers():
    """
    Get list of all domain controllers
    """
    # This would query AD or CMDB
    # Simplified example:
    return ['DC01', 'DC02', 'DC03']


def create_timeline(container):
    """
    Create incident timeline for investigation
    """
    phantom.add_note(container, '''
INCIDENT TIMELINE (Preliminary):

T-30d: Review logs from 30 days ago (max Kerberos ticket lifetime)
T-24h: Focus investigation on last 24 hours
T-0: Golden Ticket detection

Next: Map attacker activity timeline
    ''', note_type='general')
```

---

## Summary - SOAR Playbook Catalog

| Playbook | Automation Level | Approval Required | Actions | Use Case |
|----------|------------------|-------------------|---------|----------|
| Privilege Escalation | Semi-Auto | Yes (for disable) | Disable, Remove Groups, Evidence | UC-AA-001, UC-AA-002 |
| Kerberoasting | Fully Auto | No | Disable, Isolate, Reset SPNs | UC-KRB-001 |
| Unauthorized Tools | Semi-Auto | No | Isolate, Disable, Evidence | UC-POL-001 |
| SMB Lateral Movement | Fully Auto | No | Isolate, Block, Scan | UC-NET-001 |
| Golden Ticket | Manual (Evidence Auto) | Yes (for domain actions) | Preserve Evidence, Isolate | UC-KRB-002 |
| Phishing | Fully Auto | No | Delete Email, Disable, Reset | UC-PHI-001 |
| Compromised Account | Semi-Auto | Conditional | Disable, Reset, Review | UC-CA-001 |

---

**Playbook Repository Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOAR Engineering Team
**Total Playbooks**: 10+
