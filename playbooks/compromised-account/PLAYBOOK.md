# Compromised Account Response Playbook

## Overview

**Incident Type**: Compromised User Account
**Last Updated**: 2025-12-14
**Owner**: SOC Team / Identity Team
**Review Frequency**: Quarterly

### Scope

This playbook covers response to compromised user accounts including:
- Stolen credentials (phishing, breach, brute force)
- Account takeover
- Unauthorized access
- Credential stuffing attacks
- Session hijacking
- Insider misuse of credentials

---

## Incident Classification

### Severity Criteria

**Critical (P1)**:
- Executive (C-level, VP) account compromised
- Domain Admin / privileged account compromised
- Active unauthorized access with data exfiltration
- Attacker has changed credentials/locked out user
- Multiple high-value accounts compromised simultaneously
- Ransomware deployment from compromised account

**High (P2)**:
- IT Admin or privileged account compromised
- Finance/HR account with sensitive data access
- Confirmed malicious actions taken (emails sent, files accessed)
- Account used to pivot to additional systems
- VPN/Remote access account compromised
- Customer-facing system account compromised

**Medium (P3)**:
- Standard user account compromised
- No malicious actions detected yet
- Suspicious login activity (impossible travel, new location)
- Brute force successful after multiple attempts
- Account credentials found in breach database

**Low (P4)**:
- Suspicious but unconfirmed activity
- Single failed login from unusual location
- Password reset requested from unknown device
- Inactive/dormant account accessed

### Common Indicators

**Authentication Anomalies**:
- Login from unusual geographic location
- Impossible travel (two distant locations in short time)
- Login from suspicious IP/VPN/Tor exit node
- Login at unusual time for user
- Multiple failed login attempts followed by success
- Login from new device/OS/browser
- Concurrent sessions from different locations

**Account Behavior Anomalies**:
- Unusual email activity (mass sends, deletions, rules)
- Bulk file downloads
- Permission changes (shares, delegates)
- MFA disabled or changed
- Password changed without user request
- OAuth applications authorized
- Forwarding rules created
- VPN connections from new locations

**Technical Indicators**:
- User-Agent string anomalies
- Known malicious IP addresses
- Credentials in breach databases
- SIEM correlation alerts
- Threat intelligence matches

---

## Phase 1: Detection & Triage (0-15 minutes)

### Objective
Confirm account compromise and assess immediate risk

### Detection Methods

1. **SIEM Alert**: Anomalous authentication detected
2. **User Report**: User reports unauthorized access
3. **IT Helpdesk**: Password reset request from unusual source
4. **Threat Intelligence**: Credentials found in breach
5. **EDR Alert**: Suspicious activity from user's system
6. **Impossible Travel Alert**: Logins from distant locations

### Triage Steps

#### 1. Create JIRA Ticket

```
Issue Type: Alert
Summary: Compromised Account - [username]
Incident Category: Compromised Account
Detection Source: [SIEM / User Report / Threat Intel]
Affected Assets: [username, systems accessed]
Incident Severity: [TBD based on analysis]
```

#### 2. Verify Compromise Indicators

**Check recent authentication events**:

```powershell
# Azure AD sign-ins
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'user@company.com'" -Top 50 |
  Select UserPrincipalName, CreatedDateTime, IPAddress, Location, Status

# On-prem AD (last 100 logons)
Get-EventLog Security -InstanceId 4624 -Newest 100 |
  Where-Object {$_.Message -like "*user@company.com*"}
```

**Look for**:
- Geographic anomalies (new countries/cities)
- IP address anomalies (known bad IPs)
- Time anomalies (logins at 3 AM for 9-5 employee)
- Device anomalies (new OS, browser)
- Concurrent sessions from different locations
- Failed attempts followed by success

#### 3. Contact User (High Priority)

**Call or message user directly** (not via email - account may be compromised):

```
Questions to ask:
1. Are you currently logged in? From where?
2. Did you recently change your password?
3. Did you recently travel or change location?
4. Are you using a VPN or remote access?
5. Did you authorize any new applications?
6. Have you noticed anything unusual with your account?
7. Did you receive any suspicious emails or links recently?
```

**Document user responses in JIRA**

#### 4. Check for Active Sessions

**Identify active sessions**:

```powershell
# Azure AD - Get active sessions
Get-AzureADUser -ObjectId user@company.com |
  Get-AzureADUserOAuth2PermissionGrant

# Check for active tokens
Get-AzureADUserRefreshToken -ObjectId user@company.com
```

**If suspicious session active** → Proceed to immediate containment

#### 5. Assess Privilege Level

**Determine account permissions**:

```powershell
# Check AD group memberships
Get-ADUser -Identity username -Properties MemberOf |
  Select -ExpandProperty MemberOf

# Check Azure AD roles
Get-AzureADUserMembership -ObjectId user@company.com

# Check privileged access
# Is user in: Domain Admins, Enterprise Admins, Administrators?
```

**Update severity based on privilege level**

### Decision Point

**Is the account compromised?**

✅ **YES - CONFIRMED** → Immediate containment
- Unauthorized access confirmed
- User confirms they didn't perform actions
- Impossible travel detected
- Known malicious IP

❌ **NO - False Positive** → Close ticket
- User confirms legitimate activity
- VPN/travel explains location
- IT action explains password change

⚠️ **SUSPECTED - Not Confirmed** → Continue investigation
- Unusual but possible legitimate activity
- Proceed with enhanced monitoring

---

## Phase 2: Investigation (Parallel with Containment)

### Objective
Understand scope of compromise and attacker actions

### Investigation Checklist

#### 1. Timeline Construction

**Build timeline of events**:

```
Start: [First suspicious activity]
End: [Current time / detection time]

Events to include:
  - All login attempts (successful and failed)
  - Password changes
  - MFA changes
  - Email activity
  - File access
  - Permission changes
  - System access
```

**Tools**:
- SIEM for correlation
- Authentication logs
- Mailbox audit logs
- File access logs
- EDR timeline (if system compromised)

#### 2. Determine Access Vector

**How were credentials compromised?**

```
Common vectors:
□ Phishing (check for recent phishing emails to user)
□ Credential stuffing (check for breach databases)
□ Brute force (check failed login attempts)
□ Malware (check EDR on user's system)
□ Session hijacking (check for suspicious cookies/tokens)
□ Insider threat (check for policy violations)
□ Third-party breach (check external services)
□ Password reuse (ask user about password practices)
```

**Check breach databases**:
```
Tools:
- Have I Been Pwned API
- DeHashed
- Internal breach intelligence
- Dark web monitoring

Query for: user@company.com or username
```

#### 3. Enumerate Compromised Assets

**What did the attacker access?**

**Email Activity**:
```powershell
# Search mailbox audit log
Search-MailboxAuditLog -Identity user@company.com `
  -LogonTypes Owner,Admin,Delegate `
  -ShowDetails `
  -StartDate (Get-Date).AddDays(-7)

Check for:
□ Emails read (sensitive information accessed?)
□ Emails sent (spam, phishing, BEC?)
□ Emails deleted (evidence destruction?)
□ Inbox rules created (persistence, forwarding)
□ Folders accessed
```

**File Access**:
```
SIEM Query for user:
  - SharePoint/OneDrive access
  - File server access
  - Cloud storage access (Box, Dropbox, etc.)
  - Download events (large volumes?)
  - Share creation (external sharing?)

Time Range: [First compromise to present]
```

**System Access**:
```
Check for access to:
□ VPN connections
□ Remote Desktop sessions
□ Application logins (SaaS, internal apps)
□ Database queries
□ Admin consoles
□ Source code repositories
```

**Permission Changes**:
```powershell
# Check for permission changes
Get-Mailbox user@company.com | Get-MailboxPermission
Get-Mailbox user@company.com | Get-RecipientPermission

# Check mailbox rules
Get-InboxRule -Mailbox user@company.com

# Check forwarding
Get-Mailbox user@company.com | Select ForwardingAddress, ForwardingSmtpAddress

# Check OAuth apps
Get-AzureADUser -ObjectId user@company.com |
  Get-AzureADUserOAuth2PermissionGrant
```

#### 4. Check for Lateral Movement

**Did attacker pivot to other accounts/systems?**

```
SIEM Queries:
1. From compromised user's IP:
   - Attempts to access other accounts
   - Port scans
   - SMB connections
   - Authentication attempts

2. From compromised account:
   - Password spray attempts
   - Kerberos ticket requests (Golden/Silver ticket?)
   - Admin tool usage (PsExec, WMI, PowerShell Remoting)

3. Timeline correlation:
   - Did other accounts show suspicious activity around same time?
```

**Check for privilege escalation attempts**:
```
□ Attempts to access admin consoles
□ Attempts to elevate permissions
□ Group membership change attempts
□ Kerberoasting activity
□ Pass-the-hash indicators
```

#### 5. Data Exfiltration Check

**Was data stolen?**

```
Network Traffic Analysis:
□ Large outbound transfers
□ Connections to cloud storage (Google Drive, Dropbox, etc.)
□ Connections to file sharing sites
□ Encrypted tunnels
□ DNS tunneling

DLP Alerts:
□ Sensitive data email sends
□ Bulk file downloads
□ USB usage
□ Print to PDF

Email Analysis:
□ Emails with large attachments sent externally
□ Unusual recipients
□ Auto-forwarding rules
```

#### 6. Document Findings

**Update JIRA with**:

```
Investigation Summary:
- Access Vector: [How credentials compromised]
- First Compromise: [Date/Time]
- Last Activity: [Date/Time]
- Duration: [Time span]
- Systems Accessed: [List]
- Data Accessed: [List/Type]
- Actions Taken by Attacker: [List]
- Lateral Movement: [Yes/No - Details]
- Data Exfiltration: [Yes/No - Details]

MITRE ATT&CK Mapping:
- T1078: Valid Accounts
- T1110: Brute Force (if applicable)
- T1566: Phishing (if vector)
- T1534: Internal Spearphishing (if lateral movement)
- [Additional techniques]
```

---

## Phase 3: Containment (IMMEDIATE - 0-15 minutes)

### Objective
Stop attacker access immediately

⚠️ **CRITICAL**: Containment actions should begin IMMEDIATELY upon confirmation, parallel with investigation

### Immediate Containment (First 5 minutes)

#### 1. Revoke All Active Sessions

**Azure AD / O365**:
```powershell
# Revoke ALL refresh tokens and sessions
Revoke-AzureADUserAllRefreshToken -ObjectId user@company.com

# This forces re-authentication on all devices
```

**On-Premises AD**:
```powershell
# Reset Kerberos keys (invalidates all tickets)
Set-ADUser -Identity username -Replace @{msDS-KeyVersionNumber=0}

# Force password change at next logon (if not done below)
Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

#### 2. Disable Account (Temporary)

```powershell
# Azure AD
Set-AzureADUser -ObjectId user@company.com -AccountEnabled $false

# On-Prem AD
Disable-ADAccount -Identity username

# Verify
Get-AzureADUser -ObjectId user@company.com | Select UserPrincipalName, AccountEnabled
```

**Notify user**: "Your account has been temporarily disabled for security reasons. We'll contact you shortly."

#### 3. Reset Password

```powershell
# Generate strong temporary password
$tempPassword = ConvertTo-SecureString -String "$(New-Guid)!Aa1" -AsPlainText -Force

# Azure AD
Set-AzureADUserPassword -ObjectId user@company.com `
  -Password $tempPassword `
  -ForceChangePasswordNextSignIn $true

# On-Prem AD
Set-ADAccountPassword -Identity username `
  -NewPassword $tempPassword `
  -Reset

Set-ADUser -Identity username -ChangePasswordAtLogon $true
```

**Securely deliver temp password** to user via:
- Phone call
- SMS (if verified number)
- In-person
- Encrypted email to alternate address

**NOT via**: Email to compromised account!

#### 4. Remove Persistence Mechanisms

**Email Forwarding & Rules**:
```powershell
# Remove forwarding
Set-Mailbox -Identity user@company.com `
  -ForwardingAddress $null `
  -ForwardingSmtpAddress $null `
  -DeliverToMailboxAndForward $false

# Remove ALL inbox rules (review first if possible)
Get-InboxRule -Mailbox user@company.com | Remove-InboxRule -Confirm:$false

# Remove delegates
Get-MailboxPermission -Identity user@company.com |
  Where-Object {$_.User -ne "NT AUTHORITY\SELF"} |
  Remove-MailboxPermission -Confirm:$false
```

**OAuth Applications**:
```powershell
# List OAuth apps
$apps = Get-AzureADUser -ObjectId user@company.com |
  Get-AzureADUserOAuth2PermissionGrant

# Review and remove suspicious apps
# Be careful not to remove legitimate apps (Outlook, Teams, etc.)
Remove-AzureADOAuth2PermissionGrant -ObjectId [suspicious-app-id]
```

### Extended Containment (Next 10-30 minutes)

#### 5. Network-Level Blocks

**If attacker IP known**:
```
□ Block IP at firewall
□ Block IP at proxy
□ Add IP to threat intelligence feed
□ Block IP in cloud services (Azure AD, AWS, etc.)
```

#### 6. Isolate Affected Systems

**If user's endpoint compromised**:
```
□ Isolate via EDR (network containment)
□ Disconnect from network if no EDR
□ Preserve memory (don't shut down if forensics needed)
□ Image disk if necessary
```

**EDR Isolation**:
```
# Example: Isolate with Microsoft Defender
# Via Security Center UI or API
Isolate-Device -DeviceId [device-id] -Comment "Compromised account incident"
```

#### 7. Monitor for Reinfection Attempts

**Set up enhanced monitoring**:

```
SIEM Alert: Compromised Account Monitoring
Trigger: Any of the following for user@company.com:
  - Login attempt (any source)
  - Password reset attempt
  - MFA change request
  - Account re-enabled (unless by authorized admin)
  - Any authentication event

Action: Alert SOC immediately
Priority: Critical
```

---

## Phase 4: Eradication

### Objective
Remove all attacker access and prepare for safe recovery

### Eradication Steps

#### 1. Comprehensive Password Reset

**Not just the compromised account**:

```
If privileged account compromised:
  □ Reset ALL privileged account passwords
  □ Reset service account passwords
  □ Rotate API keys and secrets
  □ Reset KRBTGT password (if domain compromise suspected)

If password reuse suspected:
  □ Reset user's password on ALL internal systems
  □ Advise user to change passwords on external sites
```

#### 2. Revoke and Reissue Credentials

```
□ Revoke VPN certificates
□ Revoke SSH keys
□ Rotate API keys
□ Reissue hardware tokens if applicable
□ Reset application-specific passwords
```

#### 3. Re-register MFA

```powershell
# Force MFA re-registration
Set-MsolUser -UserPrincipalName user@company.com `
  -StrongAuthenticationMethods @()

# User must re-register MFA on next login
```

**Verify with user**:
- Remove old MFA devices
- Register new/verified device only
- Use authenticator app (not SMS if possible)

#### 4. Remove All Persistence

**Comprehensive cleanup**:

```
Email:
  ✓ All inbox rules removed
  ✓ No forwarding configured
  ✓ No unusual delegates
  ✓ Sent items reviewed for malicious emails
  ✓ OAuth apps reviewed and suspicious removed

Systems:
  □ Scheduled tasks (if system compromised)
  □ Startup items
  □ Registry persistence
  □ Malware removed
  □ Backdoor accounts removed (if created)

Cloud:
  □ Unauthorized shares removed
  □ External sharing reviewed
  □ App permissions reviewed
  □ Service principal/app registrations reviewed
```

#### 5. Endpoint Remediation

**If user's device compromised**:

```
Option 1: Reimage (Recommended)
  1. Backup user data (scan first!)
  2. Reimage from known-good source
  3. Reinstall applications
  4. Restore data (after scanning)
  5. Full EDR/AV scan

Option 2: Thorough Cleaning
  1. Full antivirus scan (multiple engines)
  2. EDR remediation
  3. Remove persistence mechanisms
  4. Update all software
  5. Verify no remaining IOCs
  6. Extended monitoring
```

#### 6. Verify Eradication

**Checklist**:
```
□ All active sessions terminated
□ Password changed and verified
□ MFA re-registered
□ Persistence mechanisms removed
□ Endpoint clean (or reimaged)
□ No remaining IOCs in environment
□ Monitoring confirms no suspicious activity
□ User confirms they have access
□ Account functions normally
```

---

## Phase 5: Recovery

### Objective
Restore account to normal operation safely

### Recovery Steps

#### 1. Enable Account

```powershell
# After password reset and MFA setup
Set-AzureADUser -ObjectId user@company.com -AccountEnabled $true

# Verify
Get-AzureADUser -ObjectId user@company.com | Select UserPrincipalName, AccountEnabled
```

#### 2. Restore Permissions

**If permissions were reduced during containment**:

```
□ Re-add to security groups
□ Restore mailbox permissions (if removed)
□ Restore SharePoint/OneDrive permissions
□ Restore application access
□ Restore VPN/remote access

CAUTION: Only restore necessary permissions
This is a good time to review principle of least privilege
```

#### 3. User Communication & Support

**Walk user through recovery**:

```
Meeting/Call with user:
1. Explain what happened
2. Provide new credentials securely
3. Walk through MFA re-registration
4. Verify they can access systems
5. Review security best practices
6. Answer questions
7. Provide ongoing support contact
```

**Provide security guidance**:
```
Email (or print) to user:
"Your account has been fully restored after security incident.

IMPORTANT - Please do the following:
1. Change passwords on ANY external sites where you used the same password
2. Enable MFA on all external accounts (email, banking, social media)
3. Review your accounts for unauthorized activity
4. Be extra vigilant for phishing attempts
5. Report any suspicious activity immediately

Security Best Practices:
- Use unique passwords for each site
- Use a password manager
- Never click links in unexpected emails
- Verify requests before sharing information
- Keep MFA enabled

Questions? Contact: security@company.com"
```

#### 4. Restore Normal Operations

```
□ User can log in successfully
□ Email functioning normally
□ File access working
□ Applications accessible
□ VPN/remote access working
□ No error messages or issues
□ User comfortable with new password/MFA
```

#### 5. Enhanced Monitoring Period

**Monitor for 7-14 days**:

```
SIEM Alerts:
  - Login from unusual location
  - Failed MFA attempts
  - Inbox rule creation
  - OAuth app authorization
  - Large file downloads
  - Bulk email sends
  - VPN from new location
  - Any anomalous activity

Alert SOC immediately if any trigger
```

#### 6. Follow-up Check-ins

```
Day 1: Call user - verify everything working
Day 3: Check SIEM - any suspicious activity?
Day 7: Call user - any issues?
Day 14: Final check - remove enhanced monitoring if clean
```

---

## Phase 6: Post-Incident Activities

### Objective
Learn and improve defenses

### Post-Incident Tasks

#### 1. Complete Post-Incident Review

**Create PIR in Confluence**:

```markdown
# PIR - Compromised Account - [username]

## Summary
- User: [username]
- Severity: [level]
- Access Vector: [how compromised]
- Duration: [time from compromise to recovery]
- Data Accessed: [summary]
- Data Exfiltrated: [Yes/No/Unknown]

## Timeline
[Detailed timeline]

## What Went Well
[Successes in detection and response]

## What Could Be Improved
[Areas for improvement]

## Root Cause
[Why did this happen?]

## Lessons Learned
[Key takeaways]

## Action Items
[Follow-up tasks with owners and due dates]
```

#### 2. Threat Intelligence Update

```
□ Document IOCs (IPs, domains, user-agents, etc.)
□ Share with threat intel platforms
□ Update internal threat feed
□ Share with ISAC/industry groups if appropriate
□ Create SIEM correlation rules

MITRE ATT&CK Mapping:
- T1078: Valid Accounts
- [Additional techniques observed]
```

#### 3. Detection Improvement

**Update detection rules**:

```
Create/enhance alerts for:
□ Impossible travel detection
□ Anomalous authentication patterns
□ Privilege escalation attempts
□ Unusual email activity
□ OAuth app authorizations
□ Inbox rule creation
□ Forwarding rule creation
□ Bulk downloads
□ Similar patterns to this incident
```

**Example SIEM Rule**:
```
Rule: Impossible Travel Detection
Logic:
  IF user login from Location A
  AND same user login from Location B
  AND distance > 500 km
  AND time between logins < time to travel
  THEN Alert: Impossible Travel - Possible Account Compromise
```

#### 4. Process Improvements

**Recommendations may include**:

```
Technical:
□ Enforce MFA org-wide
□ Implement conditional access policies
□ Deploy passwordless authentication
□ Enhance anomaly detection
□ Implement Zero Trust architecture
□ Deploy CASB for cloud security
□ Improve endpoint protection

Process:
□ Faster credential reset procedure
□ Improve user reporting process
□ Better communication templates
□ Streamline containment actions
□ Regular access reviews

Training:
□ Password hygiene training
□ Phishing awareness
□ MFA importance
□ Reporting procedures
□ Social engineering awareness
```

#### 5. User Education

**For compromised user**:
```
Required actions:
□ 1-on-1 security awareness session
□ Review incident details (what to look for)
□ Password manager training
□ MFA setup assistance
□ Additional phishing training if applicable
```

**For all users** (if widespread issue):
```
Security awareness email:
"Account Compromise Awareness

A recent incident highlighted the importance of account security.

Protect your account:
✓ Use unique, strong passwords
✓ Enable MFA everywhere
✓ Use a password manager
✓ Be suspicious of unexpected emails
✓ Report suspicious activity immediately

[Link to security resources]"
```

#### 6. Organizational Actions

**Based on root cause**:

```
If credential stuffing:
  → Dark web monitoring service
  → Password breach database monitoring
  → Force password resets for breached credentials

If phishing:
  → Enhanced email security
  → Phishing simulation program
  → Link protection/URL rewriting

If brute force:
  → Account lockout policies
  → IP-based blocking
  → Rate limiting

If weak password:
  → Enforce password complexity
  → Implement password history
  → Deploy password strength checking
```

#### 7. Update Playbook

```
Review this incident:
□ Did playbook cover all scenarios?
□ Were any steps missing or unclear?
□ What worked well?
□ What should be added/changed?
□ Update playbook accordingly
□ Train team on updates
```

---

## Escalation Criteria

### Escalate to IR Team Lead if:

- ✅ Privileged/admin account compromised
- ✅ Data exfiltration confirmed
- ✅ Multiple accounts compromised
- ✅ Lateral movement detected
- ✅ Unable to contain within 1 hour
- ✅ Attacker maintains access after initial remediation
- ✅ Domain-level compromise suspected

### Escalate to Management if:

- ✅ Executive account compromised
- ✅ Sensitive data accessed/exfiltrated
- ✅ Financial loss or fraud
- ✅ Regulatory implications (PII, PHI, PCI, etc.)
- ✅ Customer impact
- ✅ Media/PR risk

### Escalate to Legal/Compliance if:

- ✅ PII, PHI, or financial data compromised
- ✅ Regulatory reporting required
- ✅ Breach notification thresholds met
- ✅ Law enforcement involvement needed

---

## Tools & Resources

### Primary Tools

**Investigation**:
- SIEM (correlation and timeline)
- Azure AD / Active Directory logs
- Mailbox audit logs
- EDR platform
- Network traffic analysis
- Breach databases (Have I Been Pwned, DeHashed)

**Containment**:
- Azure AD PowerShell / Graph API
- Active Directory PowerShell
- Email admin console
- EDR console
- Firewall/proxy management

**Communication**:
- JIRA (incident tracking)
- Secure messaging (for user contact)
- Email (notifications)

### Reference Materials

- [MITRE ATT&CK - Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/)
- [Azure AD Sign-in Logs Documentation](https://docs.microsoft.com/azure/active-directory/reports-monitoring/concept-sign-ins)
- [Microsoft 365 Audit Log](https://docs.microsoft.com/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance)
- [Have I Been Pwned](https://haveibeenpwned.com/)

---

## Metrics

**Track these metrics**:
- Time to detect
- Time to contain
- Time to eradicate
- Time to recover
- Total MTTR
- Access vector distribution
- Detection source
- Data accessed/exfiltrated
- Privilege level of compromised accounts
- Recurrence rate

**Target SLAs**:
- Critical: Contain within 15 min
- High: Contain within 1 hour
- Medium: Contain within 4 hours

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-14 | SOC Team | Initial creation |

---

**Playbook Owner**: SOC Team / Identity Team
**Next Review**: 2026-03-14
