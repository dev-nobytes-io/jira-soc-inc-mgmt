# Phishing & Social Engineering Response Playbook

## Overview

**Incident Type**: Phishing / Social Engineering Attack
**Last Updated**: 2025-12-14
**Owner**: SOC Team
**Review Frequency**: Quarterly

### Scope

This playbook covers:
- Email phishing attacks
- Spear phishing
- Credential harvesting
- Business Email Compromise (BEC)
- Smishing (SMS phishing)
- Vishing (voice phishing)
- Malicious attachments

---

## Incident Classification

### Severity Criteria

**Critical (P1)**:
- C-level executive credentials compromised
- Successful wire transfer fraud
- Mass credential harvest (>50 users)
- Active credential use detected
- Sensitive data exfiltrated via phishing

**High (P2)**:
- Privileged account credentials harvested
- Multiple users clicked/entered credentials
- Malware executed from phishing email
- Financial/payment systems targeted
- Customer-facing systems compromised

**Medium (P3)**:
- Single user credentials potentially compromised
- User clicked link but didn't enter credentials
- Standard user account targeted
- Suspicious attachment detected but not executed

**Low (P4)**:
- User reported suspicious email
- Phishing email blocked by gateway
- No user interaction
- Generic phishing template (not targeted)

**Informational (P5)**:
- Spam misclassified as phishing
- Legitimate email reported by user
- Awareness/training opportunity

### Common Indicators

**Email Indicators**:
- Sender address spoofing or lookalike domain
- Urgent language ("verify immediately", "account suspended")
- Generic greetings ("Dear customer")
- Spelling/grammar errors
- Unexpected attachments
- Shortened or obfuscated URLs
- Requests for credentials or sensitive information
- Mismatched display name and email address

**Technical Indicators**:
- Malicious URLs in email body
- Suspicious attachment types (.exe, .scr, .zip with macros)
- Email authentication failures (SPF, DKIM, DMARC)
- Recently registered domains
- Known bad sender IPs
- Suspicious email headers

---

## Phase 1: Detection & Triage (0-15 minutes)

### Objective
Verify phishing attack and assess initial scope

### Detection Methods

1. **User Report**: User forwards suspicious email
2. **Email Gateway Alert**: Blocked/quarantined message
3. **SIEM Alert**: Suspicious email patterns detected
4. **Threat Intelligence**: Known phishing campaign match

### Triage Steps

#### 1. Create JIRA Ticket

```
Issue Type: Alert
Summary: Phishing - [Brief description]
Incident Category: Phishing/Social Engineering
Detection Source: [User Report / Email Gateway / SIEM]
Incident Severity: [TBD based on analysis]
```

#### 2. Initial Email Analysis

**Analyze the email**:
```
□ Sender address (check for spoofing)
□ Reply-to address (often different from sender)
□ Subject line
□ Email body content
□ Links (URLs) - DO NOT CLICK
□ Attachments - DO NOT OPEN
□ Email headers (full headers)
□ Recipient list (targeted vs mass)
```

**Extract Email Headers**:
```
Authentication Results:
  SPF: [Pass/Fail/None]
  DKIM: [Pass/Fail/None]
  DMARC: [Pass/Fail/None]

Originating IP: [IP address]
Return-Path: [email]
Reply-To: [email]
```

#### 3. URL Analysis (if applicable)

**For each URL in email**:

```bash
# Extract actual URL (don't click!)
# Right-click → Copy link address

# Analyze with VirusTotal (via API or web)
curl -X POST 'https://www.virustotal.com/vtapi/v2/url/scan' \
  -d apikey=YOUR_API_KEY \
  -d url='http://suspicious-url.com'

# Check URL reputation
# Use URLScan.io, Any.Run, or similar
```

**Check for**:
- Recently registered domain (< 30 days)
- Typosquatting (slight misspelling of legitimate domain)
- Suspicious TLD (.tk, .ml, .ga, etc.)
- HTTPS usage (even phishing uses HTTPS now)
- Redirects to credential forms

#### 4. Attachment Analysis (if applicable)

**Do NOT open directly on your system**

```bash
# Get file hash
Get-FileHash suspicious_file.exe -Algorithm SHA256

# Check hash with VirusTotal
curl -X POST 'https://www.virustotal.com/vtapi/v2/file/report' \
  -d apikey=YOUR_API_KEY \
  -d resource=FILE_HASH

# Analyze in sandbox (Any.Run, Joe Sandbox, etc.)
# Upload to sandbox for detonation
```

**Check for**:
- Known malware hashes
- Suspicious file types
- Macros in documents
- Embedded executables

#### 5. Determine Scope

**How many users received it?**

```
Email Gateway Query:
Search for:
  Sender: [phishing email address]
  Subject: [phishing subject]
  Timeframe: [Last 24-48 hours]

Count total recipients
```

**Who interacted with it?**

```
SIEM/Proxy Query:
Search for:
  URL access: [phishing domain]
  User: [all users]
  Timeframe: [Last 24 hours]

Identify users who clicked links
```

**Update JIRA**:
```
Affected Assets: [List of users/systems]
Indicators of Compromise:
  - Sender: [email]
  - URLs: [list]
  - Hashes: [list]
  - Domains: [list]
```

### Decision Point

**Is this a true phishing attempt?**

✅ **YES** → Proceed to Investigation
- Malicious intent confirmed
- Users at risk or compromised

❌ **NO** (False Positive) → Close ticket
- Legitimate email misidentified
- Benign email
- Update False Positive Reason in JIRA
- Provide feedback to reporting user

**Unsure?** → Escalate to Tier 2 for deeper analysis

---

## Phase 2: Investigation (15 minutes - 2 hours)

### Objective
Determine if credentials were compromised and identify affected accounts

### Investigation Checklist

#### 1. Identify User Interaction

**Query proxy/web logs**:
```
Search for access to phishing domain:
  Domain: [phishing-domain.com]
  Timeframe: [Email send time + 48 hours]

Results: List of usernames who accessed URL
```

**Check email gateway logs**:
```
Query for:
  - Who opened the email (if tracking available)
  - Who clicked links
  - Who downloaded attachments
```

**Contact affected users** (if <10 users):
```
Email template:
"We detected a phishing email that you may have received.
Subject: [subject line]
Sender: [sender]

Did you:
1. Click any links in this email?
2. Enter your username/password?
3. Download any attachments?
4. Perform any other actions?

Please respond ASAP - this is a security incident."
```

#### 2. Check for Credential Compromise

**If user entered credentials:**

**Review authentication logs**:
```powershell
# Check for logins from unusual locations
Get-EventLog Security -InstanceId 4624 -After (Get-Date).AddDays(-1) |
  Where-Object {$_.Message -like "*username*"}

# Check failed login attempts (possible credential stuffing)
Get-EventLog Security -InstanceId 4625
```

**Check for**:
- Logins from unusual IP addresses
- Logins from unusual geographic locations
- Logins at unusual times
- Multiple failed login attempts
- Successful login followed by suspicious activity

**Cloud services (O365, Google Workspace)**:
```
Check unified audit log for:
  - Sign-in logs
  - Location of logins
  - Devices used
  - Actions performed post-login
```

#### 3. Check for Malware Execution

**If attachment was downloaded/opened:**

**Query EDR for**:
```
Host: [affected user's computer]
Timeframe: [Email receipt + 24 hours]

Look for:
  - Process creation events
  - File creation events
  - Network connections to suspicious IPs
  - Registry modifications
  - Scheduled task creation
  - PowerShell execution
```

**Scan affected system**:
```powershell
# Run AV scan
Start-MpScan -ScanType FullScan

# Check running processes
Get-Process | Where-Object {$_.Path -like "*AppData*"}

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-1)}
```

#### 4. Check for Account Abuse

**If credentials were compromised:**

**Review account activity**:
```
Email Activity:
  □ Mailbox rules created (forward, delete)
  □ Emails sent from account
  □ Emails deleted
  □ Folders created

Cloud Activity:
  □ Files shared externally
  □ Files downloaded in bulk
  □ Permission changes
  □ New applications authorized

Network Activity:
  □ VPN connections
  □ Remote access
  □ Lateral movement attempts
  □ Data transfers
```

**O365 Example**:
```powershell
# Check inbox rules
Get-InboxRule -Mailbox user@company.com

# Check for OAuth apps
Get-MsolUserOAuthApp -UserPrincipalName user@company.com

# Check mailbox audit logs
Search-MailboxAuditLog -Identity user@company.com -ShowDetails
```

#### 5. Identify Campaign Scope

**Is this a targeted or mass campaign?**

```
Threat Intelligence Check:
  □ Search for IOCs in threat intel platforms
  □ Check OSINT (Twitter, Reddit) for reports
  □ Check if other orgs reporting same campaign
  □ Identify if spear phishing or mass phishing

Internal Scope:
  □ How many employees received?
  □ How many clicked?
  □ How many entered credentials?
  □ Any patterns (department, role)?
```

**Update JIRA with findings**:
```
Investigation Notes:
  - Users who clicked: [#]
  - Credentials compromised: [#]
  - Malware executed: [Yes/No]
  - Account abuse detected: [Yes/No]
  - Campaign type: [Targeted/Mass]
```

---

## Phase 3: Containment (Immediate - 30 minutes)

### Objective
Prevent further damage and stop spread

### Containment Actions

#### 1. Block Phishing Infrastructure

**Email Gateway**:
```
□ Block sender email address
□ Block sender domain
□ Delete all unread copies from mailboxes
□ Quarantine/delete read copies if possible
□ Block phishing URLs
□ Block attachment hashes
```

**Example (Exchange)**:
```powershell
# Delete unread phishing emails
Get-Mailbox -ResultSize Unlimited |
  Search-Mailbox -SearchQuery 'Subject:"Phishing Subject" AND IsRead:false' -DeleteContent -Force

# Create transport rule to block sender
New-TransportRule -Name "Block Phishing Campaign XYZ" `
  -FromAddressContainsWords "phisher@evil.com" `
  -DeleteMessage $true
```

**Firewall/Proxy**:
```
□ Block phishing domains
□ Block phishing IPs
□ Block C2 infrastructure (if malware)
```

#### 2. Isolate Compromised Accounts

**For each compromised account**:

```powershell
# Revoke all sessions
Revoke-AzureADUserAllRefreshToken -ObjectId user@company.com

# Disable sign-in
Set-AzureADUser -ObjectId user@company.com -AccountEnabled $false

# Remove mailbox delegates if suspicious
Remove-MailboxPermission -Identity user@company.com -User delegate -AccessRights FullAccess

# Remove suspicious inbox rules
Get-InboxRule -Mailbox user@company.com | Where-Object {$_.Description -like "*forward*"} | Remove-InboxRule
```

**Check for persistence**:
```
□ Remove unauthorized inbox rules
□ Revoke suspicious OAuth applications
□ Remove mailbox delegates
□ Remove forwarding rules
□ Check for scheduled tasks (if system compromised)
```

#### 3. Isolate Infected Systems

**If malware was executed**:

```
□ Disconnect system from network
□ Do NOT power off (preserve memory)
□ Disable wireless
□ Isolate via EDR if available
```

**EDR Isolation Example**:
```
# CrowdStrike
contain-host --hostname [affected-system]

# SentinelOne
Disconnect-SentinelOneAgent -AgentId [agent-id]

# Microsoft Defender
# Use Security Center to isolate device
```

#### 4. Notify Stakeholders

**Immediate Notifications**:
```
□ SOC Team Lead
□ Incident Response Team
□ IT Support (for password resets)
□ Affected users' managers (if critical)
□ Security awareness team
```

**Communication Template**:
```
Subject: URGENT - Phishing Incident Response

A phishing campaign has been detected affecting [#] employees.

Current Status:
- Severity: [Level]
- Credentials Compromised: [#]
- Malware Detected: [Yes/No]
- Containment: [In Progress/Complete]

Actions Taken:
- [List key containment actions]

Next Steps:
- [Eradication plan]

Estimated Resolution: [Time]
```

---

## Phase 4: Eradication

### Objective
Remove attacker access and malicious artifacts

### Eradication Steps

#### 1. Force Password Resets

**For all compromised accounts**:

```powershell
# Reset password (AD)
Set-ADAccountPassword -Identity username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "TempP@ss123!" -Force)

# Force change at next logon
Set-ADUser -Identity username -ChangePasswordAtLogon $true

# Azure AD
Set-AzureADUserPassword -ObjectId user@company.com -Password $newPassword -ForceChangePasswordNextSignIn $true
```

**Password reset communication**:
```
Email to user:
"Your account has been compromised in a phishing incident.

Your password has been reset to: [temp password]

You MUST change your password immediately upon next login.

Choose a strong, unique password not used elsewhere.

If you have used this password on other sites, change those immediately.

Security Team"
```

#### 2. Enable MFA (if not already enabled)

```powershell
# Enable MFA for affected users
Set-MsolUser -UserPrincipalName user@company.com -StrongAuthenticationRequirements $true

# Require re-registration
Reset-MsolStrongAuthenticationMethodByUpn -UserPrincipalName user@company.com
```

#### 3. Review and Remove Persistence

**Check for persistence mechanisms**:

```
Email:
  □ Remove malicious inbox rules
  □ Remove unauthorized delegates
  □ Remove forwarding addresses
  □ Revoke unauthorized OAuth apps

Systems:
  □ Remove scheduled tasks
  □ Remove registry persistence
  □ Remove startup items
  □ Remove malicious services
```

**Remove malicious inbox rules**:
```powershell
# List all inbox rules
Get-InboxRule -Mailbox user@company.com | Select Name, Description, ForwardTo

# Remove suspicious rules
Remove-InboxRule -Mailbox user@company.com -Identity "Rule Name"
```

**Remove OAuth applications**:
```powershell
# List OAuth apps
Get-MsolUserOAuthApp -UserPrincipalName user@company.com

# Remove suspicious app
Remove-MsolUserOAuthApp -UserPrincipalName user@company.com -AppId [app-id]
```

#### 4. Malware Removal (if applicable)

**If system infected**:

```
Option 1: EDR Remediation
  - Use EDR to quarantine/delete malware
  - Verify removal with full scan
  - Check for additional IOCs

Option 2: Reimage
  - For critical infections
  - Backup user data (scan first!)
  - Reimage from known good source
  - Restore data after scanning
  - Reinstall applications

Option 3: Manual Removal
  - Identify malware location
  - Stop malicious processes
  - Delete files
  - Remove persistence
  - Full AV scan
```

#### 5. Domain/IP Blocks

**Long-term blocks**:
```
□ Add phishing domains to blocklist
□ Add C2 IPs to firewall deny rules
□ Update email gateway reputation
□ Share IOCs with threat intel platforms
```

---

## Phase 5: Recovery

### Objective
Restore normal operations safely

### Recovery Steps

#### 1. Re-enable Accounts

**After password reset and MFA setup**:

```powershell
# Enable account
Set-AzureADUser -ObjectId user@company.com -AccountEnabled $true

# Verify MFA configured
Get-MsolUser -UserPrincipalName user@company.com | Select StrongAuthenticationMethods

# Test login
```

#### 2. Restore System Access

**If system was isolated**:

```
□ Verify malware removed
□ Full AV scan complete
□ EDR sensors active
□ Reconnect to network
□ Monitor for 24-48 hours
```

#### 3. Restore Email Services

```
□ Verify no malicious rules
□ Verify no forwarding
□ Check sent items for spam
□ Monitor for suspicious activity
```

#### 4. User Communication

```
Email to affected users:
"Your account has been secured following the phishing incident.

Actions taken:
- Password reset
- MFA enabled
- Malicious access removed

You can now resume normal activities.

Please remain vigilant for:
- Additional phishing attempts
- Unexpected password reset requests
- Unusual account activity

Report anything suspicious to security@company.com

Thank you,
Security Team"
```

#### 5. Enhanced Monitoring

**Monitor for 7 days**:

```
□ Login attempts from unusual locations
□ Failed MFA attempts
□ Inbox rule creation
□ Large file downloads
□ Bulk email sends
□ OAuth app authorizations
```

**Set up alerts**:
```
SIEM Alert: Compromised Account Monitoring
Trigger: Any of the following for [user list]:
  - Login from new country
  - Failed MFA attempt
  - Inbox rule created
  - OAuth app authorized
  - Bulk download
Action: Alert SOC immediately
```

---

## Phase 6: Post-Incident Activities

### Objective
Learn from incident and improve defenses

### Post-Incident Tasks

#### 1. Complete Post-Incident Review

**Create PIR in Confluence**:
```
Title: PIR - [JIRA-XXX] - Phishing Campaign [Date]

Include:
- Timeline of events
- Number of users affected
- Attack vector details
- Response effectiveness
- Lessons learned
- Recommendations
```

#### 2. Update Threat Intelligence

```
□ Document IOCs in threat intel platform
□ Share with industry groups (ISAC, etc.)
□ Update internal threat feed
□ Add to SIEM correlation rules
```

**IOCs to document**:
```
Sender Email: [email]
Sender Domain: [domain]
Phishing URLs: [list]
Attachment Hashes: [list]
C2 IPs: [list]
MITRE ATT&CK: T1566 (Phishing)
```

#### 3. Improve Detection

**Email Gateway Tuning**:
```
□ Add sender patterns to anti-phishing rules
□ Improve URL reputation checking
□ Update attachment blocking policies
□ Enhance impersonation detection
```

**SIEM Detection Rules**:
```
Create/update alerts for:
  - Emails with similar characteristics
  - Access to lookalike domains
  - Mass credential reset requests
  - Unusual inbox rule creation
  - OAuth app authorizations
```

#### 4. User Awareness

**For all users**:
```
Send awareness email:
"Phishing Alert - [Brief Description]

A phishing campaign was recently detected targeting our organization.

Red flags included:
- [Indicator 1]
- [Indicator 2]
- [Indicator 3]

Remember:
- Verify sender before clicking links
- Hover over links to see real destination
- Don't enter credentials from email links
- Report suspicious emails

Report phishing: [reporting method]"
```

**For affected users**:
```
Provide additional training:
  - What went wrong
  - How to identify phishing
  - Hands-on phishing simulation
  - Resources for reporting
```

#### 5. Organizational Improvements

**Recommendations may include**:
```
Technical:
  □ Deploy email authentication (SPF, DKIM, DMARC)
  □ Implement link protection
  □ Deploy safe links/safe attachments
  □ Enforce MFA org-wide
  □ Improve web filtering

Process:
  □ Mandatory phishing training
  □ Regular phishing simulations
  □ Improve incident reporting process
  □ Faster credential reset process

Policy:
  □ Update acceptable use policy
  □ Clarify reporting requirements
  □ Define consequences for ignoring warnings
```

#### 6. Update Playbook

```
Based on this incident:
  □ What worked well?
  □ What could be improved?
  □ Were any steps unclear?
  □ Should steps be added/removed?
  □ Update playbook accordingly
```

---

## Escalation Criteria

### Escalate to Incident Response Team Lead if:

- ✅ 10+ users compromised
- ✅ C-level or VP credentials compromised
- ✅ Financial transaction attempted/successful
- ✅ Sensitive data exfiltrated
- ✅ Widespread malware deployment
- ✅ Advanced/targeted spear phishing (APT)
- ✅ Ongoing active use of credentials
- ✅ Unable to contain within 2 hours

### Escalate to Management if:

- ✅ Critical severity (P1)
- ✅ Potential data breach
- ✅ Legal/regulatory implications
- ✅ Customer data involved
- ✅ Financial loss occurred
- ✅ Media attention likely

### Escalate to Legal/Compliance if:

- ✅ PII/PHI compromised
- ✅ Financial data accessed
- ✅ Regulatory reporting required
- ✅ Breach notification thresholds met

---

## Communication Plan

### Internal Communication

**Immediate (0-30 min)**:
- SOC Team Lead
- On-call Incident Responder
- IT Support (for resets)

**Regular Updates (every 2 hours for P1/P2)**:
- Security Management
- IT Operations
- Affected users' managers

**Post-Incident**:
- All staff (awareness email)
- Affected users (lessons learned)

### External Communication

**When Required**:
- Legal counsel (regulatory implications)
- Law enforcement (financial fraud)
- ISAC/ISAO (share IOCs)
- Customers (if their data affected)

**Approval Required From**: CISO or Legal

**Template**:
```
External Notification:
"We are writing to inform you of a security incident that may have affected your information.

What Happened: [Brief description]
What Information: [Data types]
What We're Doing: [Response actions]
What You Should Do: [User actions]

Contact: security@company.com"
```

---

## Tools & Resources

### Primary Tools

**Email Analysis**:
- Email Gateway (Proofpoint, Mimecast, etc.)
- Email headers analyzer
- URL scanners (VirusTotal, URLScan.io)
- Attachment sandboxes (Any.Run, Joe Sandbox)

**Investigation**:
- SIEM platform
- EDR platform
- Azure AD / Active Directory logs
- Mailbox audit logs
- Proxy logs

**Containment**:
- Email gateway admin console
- Firewall management
- EDR console
- Identity management (Azure AD, Okta, etc.)

**Communication**:
- JIRA (ticket tracking)
- Slack/Teams (internal comms)
- Email (user notifications)

### Reference Materials

- [MITRE ATT&CK - Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)
- [Anti-Phishing Working Group](https://apwg.org/)
- [PhishTank](https://www.phishtank.com/)
- [VirusTotal](https://www.virustotal.com/)
- [URLScan.io](https://urlscan.io/)

### Command Reference

See [Appendix A](#appendix-a-command-reference) below

---

## Metrics

Track these metrics for continuous improvement:

- **Time to Detect**: Alert generation to SOC review
- **Time to Respond**: Review to initial action
- **Time to Contain**: Initial action to containment complete
- **Time to Eradicate**: Containment to threat removed
- **Time to Recover**: Eradication to normal operations
- **User Click Rate**: % of recipients who clicked
- **Compromise Rate**: % who entered credentials
- **Detection Source**: How incident was detected
- **False Positive Rate**: Legitimate emails reported

**Target Metrics**:
- Mean Time to Respond (MTTR): < 30 minutes
- Containment Time: < 1 hour
- User Click Rate: < 5%
- Compromise Rate: < 1%

---

## Appendix A: Command Reference

### Email Analysis (PowerShell / Exchange)

```powershell
# Search for phishing emails
Get-Mailbox -ResultSize Unlimited |
  Search-Mailbox -SearchQuery 'Subject:"Phishing Subject"' -TargetMailbox "admin@company.com" -TargetFolder "PhishingSearch"

# Delete phishing emails
Get-Mailbox -ResultSize Unlimited |
  Search-Mailbox -SearchQuery 'From:phisher@evil.com' -DeleteContent -Force

# Check inbox rules
Get-InboxRule -Mailbox user@company.com

# Remove inbox rule
Remove-InboxRule -Mailbox user@company.com -Identity "RuleName"

# Check mailbox forwarding
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingAddress -ne $null} | Select Name, ForwardingAddress

# Remove forwarding
Set-Mailbox -Identity user@company.com -ForwardingAddress $null

# Check mailbox audit log
Search-MailboxAuditLog -Identity user@company.com -LogonTypes Delegate,Admin -ShowDetails
```

### Azure AD / O365

```powershell
# Connect to Azure AD
Connect-AzureAD

# Check sign-in logs
Get-AzureADAuditSignInLogs -Filter "userPrincipalName eq 'user@company.com'"

# Disable account
Set-AzureADUser -ObjectId user@company.com -AccountEnabled $false

# Reset password
Set-AzureADUserPassword -ObjectId user@company.com -Password $newPassword -ForceChangePasswordNextSignIn $true

# Revoke sessions
Revoke-AzureADUserAllRefreshToken -ObjectId user@company.com

# Check OAuth apps
Get-AzureADUser -ObjectId user@company.com | Get-AzureADUserOAuth2PermissionGrant

# Remove OAuth app
Remove-AzureADOAuth2PermissionGrant -ObjectId [grant-id]
```

### URL Analysis

```bash
# VirusTotal URL scan
curl -X POST 'https://www.virustotal.com/vtapi/v2/url/scan' \
  -d apikey=YOUR_API_KEY \
  -d url='http://suspicious-url.com'

# Get URL report
curl -X POST 'https://www.virustotal.com/vtapi/v2/url/report' \
  -d apikey=YOUR_API_KEY \
  -d resource='http://suspicious-url.com'
```

### File Hash Analysis

```powershell
# Get file hash
Get-FileHash -Path "C:\path\to\file.exe" -Algorithm SHA256

# Check with VirusTotal
curl -X POST 'https://www.virustotal.com/vtapi/v2/file/report' \
  -d apikey=YOUR_API_KEY \
  -d resource=FILE_HASH
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-14 | SOC Team | Initial creation |

---

**Playbook Owner**: SOC Team
**Next Review**: 2026-03-14 (Quarterly)
**JIRA Link**: [Link to JIRA playbook management ticket]
