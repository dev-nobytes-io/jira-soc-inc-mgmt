# Integration Guide

## Overview

This document describes how to integrate external systems with the SOC JIRA case management system.

## Common Integrations

### 1. SIEM → JIRA (Alert Creation)
### 2. JIRA ↔ Confluence (Documentation)
### 3. JIRA → Slack/Teams (Notifications)
### 4. EDR → JIRA (Endpoint Alerts)
### 5. Email Gateway → JIRA (Phishing Reports)

---

## SIEM → JIRA Integration

### Overview

Automatically create JIRA alerts from SIEM detections.

### Methods

#### Option 1: Webhook (Recommended)

**SIEM Side Configuration (Splunk Example)**:

```spl
# Create alert action to send to JIRA
# Webhook URL: https://your-domain.atlassian.net/rest/api/3/issue

# Example saved search with alert action
index=security sourcetype=*
| search [your detection logic]
| eval severity=case(
    risk_score > 80, "Critical",
    risk_score > 60, "High",
    risk_score > 40, "Medium",
    1=1, "Low"
  )
| table _time, user, src_ip, description, severity
| sendalert jira_webhook
```

**JIRA Webhook Endpoint**:

Create incoming webhook in JIRA automation:
1. Settings → System → Webhooks
2. Create webhook
3. URL: Your webhook processor or direct API
4. Events: None (we'll call it)
5. Generate authentication token

**Webhook Payload Format**:

```json
{
  "fields": {
    "project": {
      "key": "SOC"
    },
    "summary": "SIEM Alert: {{alert_name}}",
    "description": "{{alert_description}}\n\nTime: {{_time}}\nSource: {{src_ip}}\nUser: {{user}}",
    "issuetype": {
      "name": "Alert"
    },
    "customfield_10001": "{{severity}}",
    "customfield_10002": "{{category}}",
    "customfield_10003": "SIEM",
    "customfield_10004": "{{affected_assets}}",
    "customfield_10005": "{{iocs}}"
  }
}
```

**Authentication**:

```bash
# Basic auth with API token
curl -X POST \
  -H "Content-Type: application/json" \
  -u "email@company.com:API_TOKEN" \
  -d @payload.json \
  https://your-domain.atlassian.net/rest/api/3/issue
```

#### Option 2: JIRA API Script

**Python Example**:

```python
from jira import JIRA
import os

# Connect to JIRA
jira = JIRA(
    server='https://your-domain.atlassian.net',
    basic_auth=('email@company.com', os.getenv('JIRA_API_TOKEN'))
)

# Create alert
issue_dict = {
    'project': {'key': 'SOC'},
    'summary': f'SIEM Alert: {alert_name}',
    'description': alert_description,
    'issuetype': {'name': 'Alert'},
    'customfield_10001': severity,  # Incident Severity
    'customfield_10002': category,  # Incident Category
    'customfield_10003': 'SIEM',    # Detection Source
}

new_issue = jira.create_issue(fields=issue_dict)
print(f'Created issue: {new_issue.key}')
```

**Custom Field Mapping**:

You'll need to find your custom field IDs:

```python
# Get all fields
all_fields = jira.fields()
for field in all_fields:
    print(f"{field['name']}: {field['id']}")
```

Map to your custom fields:
- `customfield_10001` = Incident Severity
- `customfield_10002` = Incident Category
- `customfield_10003` = Detection Source
- `customfield_10004` = Affected Assets
- `customfield_10005` = IOCs

---

## JIRA ↔ Confluence Integration

### Auto-Create PIR Pages

**JIRA Automation Rule**:

```
Trigger: Issue transitioned to "Closed"
Conditions:
  - Issue Type = "Incident"
  - Severity = "Critical" OR "High"

Actions:
  1. Create Confluence page
     Space: SOC
     Parent: Post-Incident Reviews / {{issue.created.year}}
     Title: PIR - {{issue.key}} - {{issue.summary}}
     Template: Post-Incident Review Template

  2. Add remote link to JIRA issue

  3. Add comment:
     "Post-Incident Review created: [View PIR]({{confluenceUrl}})"
```

**Confluence REST API** (if using custom script):

```python
import requests
import os

confluence_url = "https://your-domain.atlassian.net/wiki"
auth = ('email@company.com', os.getenv('CONFLUENCE_API_TOKEN'))

# Create page
page_data = {
    "type": "page",
    "title": f"PIR - {jira_key} - {summary}",
    "space": {"key": "SOC"},
    "ancestors": [{"id": "parent_page_id"}],
    "body": {
        "storage": {
            "value": f"<h1>PIR - {jira_key}</h1><p>Content here...</p>",
            "representation": "storage"
        }
    }
}

response = requests.post(
    f"{confluence_url}/rest/api/content",
    json=page_data,
    auth=auth,
    headers={"Content-Type": "application/json"}
)

print(f"Created page: {response.json()['_links']['webui']}")
```

### Link Playbooks to JIRA

**In Confluence**:
- Create playbook pages
- Note page URLs

**In JIRA**:
- Add playbook URLs to issue descriptions or comments
- Use automation to auto-link based on category

**Example Automation**:

```
Trigger: Issue created
Conditions:
  - Issue Type = "Incident"
  - Incident Category = "Phishing"

Actions:
  Add comment:
  "📖 Relevant Playbook: [Phishing Response Playbook](https://your-domain.atlassian.net/wiki/spaces/SOC/pages/123456/Phishing+Response)"
```

---

## JIRA → Slack/Teams Integration

### Slack Integration

**Method 1: JIRA for Slack App** (Easiest)

1. Install JIRA for Slack app
2. Connect to your JIRA instance
3. Configure notifications:
   - `/jira connect`
   - `/jira subscribe SOC`

**Method 2: Custom Webhooks**

**Create Slack Incoming Webhook**:
1. Go to Slack App settings
2. Create incoming webhook
3. Copy webhook URL

**JIRA Automation**:

```
Trigger: Issue created OR Issue updated
Conditions:
  - Issue Type = "Incident"
  - Severity = "Critical" OR "High"

Actions:
  Send web request:
    URL: {{slack_webhook_url}}
    Method: POST
    Headers: Content-Type: application/json
    Body:
    {
      "text": "🚨 Critical Incident Alert",
      "attachments": [{
        "color": "danger",
        "fields": [
          {"title": "Incident", "value": "{{issue.key}}: {{issue.summary}}", "short": false},
          {"title": "Severity", "value": "{{issue.Incident Severity}}", "short": true},
          {"title": "Category", "value": "{{issue.Incident Category}}", "short": true},
          {"title": "Assigned", "value": "{{issue.assignee.displayName}}", "short": true},
          {"title": "Status", "value": "{{issue.status.name}}", "short": true}
        ],
        "actions": [{
          "type": "button",
          "text": "View in JIRA",
          "url": "{{issue.url}}"
        }]
      }]
    }
```

### Microsoft Teams Integration

**Method 1: JIRA Cloud for Teams App**

1. Install app from Teams marketplace
2. Connect to JIRA
3. Configure channel notifications

**Method 2: Incoming Webhook**

**Create Teams Webhook**:
1. In Teams channel → Connectors
2. Add Incoming Webhook
3. Copy webhook URL

**JIRA Automation**:

```
Trigger: Issue created
Conditions:
  - Issue Type = "Incident"

Actions:
  Send web request:
    URL: {{teams_webhook_url}}
    Method: POST
    Body:
    {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      "summary": "New SOC Incident",
      "themeColor": "FF0000",
      "title": "🚨 {{issue.key}}: {{issue.summary}}",
      "sections": [{
        "facts": [
          {"name": "Severity", "value": "{{issue.Incident Severity}}"},
          {"name": "Category", "value": "{{issue.Incident Category}}"},
          {"name": "Assigned", "value": "{{issue.assignee.displayName}}"}
        ]
      }],
      "potentialAction": [{
        "@type": "OpenUri",
        "name": "View Incident",
        "targets": [{"os": "default", "uri": "{{issue.url}}"}]
      }]
    }
```

---

## EDR → JIRA Integration

### CrowdStrike Example

**Workflow**:
1. CrowdStrike detects threat
2. Sends webhook to integration service
3. Integration service creates JIRA alert

**CrowdStrike Webhook Setup**:
1. Falcon Console → Configuration → API Clients
2. Create API client
3. Configure webhook notifications

**Integration Service** (Python example):

```python
from flask import Flask, request
from jira import JIRA

app = Flask(__name__)
jira = JIRA(server='https://your-domain.atlassian.net',
            basic_auth=('email@company.com', 'API_TOKEN'))

@app.route('/crowdstrike-webhook', methods=['POST'])
def crowdstrike_webhook():
    data = request.json

    # Parse CrowdStrike alert
    severity = data.get('severity', 'Medium')
    hostname = data.get('hostname')
    description = data.get('description')

    # Create JIRA alert
    issue = jira.create_issue(
        project='SOC',
        summary=f'EDR Alert: Threat on {hostname}',
        description=description,
        issuetype={'name': 'Alert'},
        customfield_10001=severity,
        customfield_10002='Malware/Ransomware',
        customfield_10003='EDR/XDR',
        customfield_10004=hostname
    )

    return {'status': 'success', 'issue': issue.key}
```

### Microsoft Defender Example

**Use Microsoft Sentinel** (if available):
- Sentinel can forward alerts to JIRA via Logic Apps
- Configure Logic App with JIRA connector

**Or use Graph API**:

```python
# Poll for Defender alerts and create JIRA tickets
import requests

graph_api = "https://graph.microsoft.com/v1.0/security/alerts"
headers = {"Authorization": f"Bearer {access_token}"}

alerts = requests.get(graph_api, headers=headers).json()

for alert in alerts['value']:
    if alert['status'] == 'newAlert':
        create_jira_ticket(alert)
```

---

## Email Gateway → JIRA

### User Phishing Reports

**Option 1: Dedicated Email Address**

1. Create mailbox: phishing-reports@company.com
2. Users forward suspicious emails there
3. Integration script polls mailbox and creates JIRA

**Python Script**:

```python
import imaplib
import email
from jira import JIRA

# Connect to mailbox
mail = imaplib.IMAP4_SSL('imap.gmail.com')
mail.login('phishing-reports@company.com', 'password')
mail.select('inbox')

# Search for unread emails
status, messages = mail.search(None, 'UNSEEN')

for msg_num in messages[0].split():
    # Fetch email
    status, data = mail.fetch(msg_num, '(RFC822)')
    raw_email = data[0][1]
    msg = email.message_from_bytes(raw_email)

    # Create JIRA alert
    jira.create_issue(
        project='SOC',
        summary=f'Phishing Report: {msg["Subject"]}',
        description=f'Reported by: {msg["From"]}\n\n{msg.get_payload()}',
        issuetype={'name': 'Alert'},
        customfield_10002='Phishing/Social Engineering',
        customfield_10003='User Report'
    )

    # Mark as read
    mail.store(msg_num, '+FLAGS', '\\Seen')
```

**Option 2: Proofpoint / Mimecast Integration**

Most email gateways have API or webhook capabilities:

**Proofpoint TAP**:
```python
# Poll Proofpoint API for quarantined messages
import requests

pp_api = "https://tap-api-v2.proofpoint.com/v2/siem/all"
headers = {"Authorization": f"Bearer {pp_token}"}

alerts = requests.get(pp_api, headers=headers).json()

for alert in alerts['messagesDelivered']:
    create_jira_alert(alert)
```

---

## Bi-directional Integrations

### JIRA → SIEM (Status Updates)

Send JIRA status changes back to SIEM for correlation:

**JIRA Automation**:

```
Trigger: Issue transitioned
Conditions:
  - Issue Type = "Alert" OR "Incident"

Actions:
  Send web request to SIEM API:
    URL: https://siem.company.com/api/update
    Method: POST
    Body:
    {
      "jira_key": "{{issue.key}}",
      "status": "{{issue.status}}",
      "resolution": "{{issue.resolution}}",
      "timestamp": "{{now}}"
    }
```

Use in SIEM to:
- Close corresponding SIEM events
- Update case status
- Provide analyst feedback loop

---

## Authentication & Security

### API Token Management

**Best Practices**:
- Use service accounts for integrations
- Rotate API tokens regularly (quarterly)
- Store tokens in secrets manager (not code)
- Use least privilege (minimal permissions)
- Monitor API usage

**Create JIRA API Token**:
1. Account Settings → Security
2. Create API token
3. Store securely (e.g., AWS Secrets Manager, Azure Key Vault)

**Use in Code**:

```python
import os
from jira import JIRA

# Don't hardcode!
jira = JIRA(
    server='https://your-domain.atlassian.net',
    basic_auth=(
        os.getenv('JIRA_USER'),
        os.getenv('JIRA_API_TOKEN')
    )
)
```

### Network Security

**Whitelist IPs**:
- Configure JIRA to only accept webhooks from known IPs
- Use VPN or private networking when possible

**Use HTTPS**:
- All integrations must use HTTPS
- Validate SSL certificates

**Webhook Security**:
- Use webhook secrets/signatures
- Validate incoming requests

---

## Testing Integrations

### Test Checklist

- [ ] Create test issue via integration
- [ ] Verify all fields populated correctly
- [ ] Verify automation rules trigger
- [ ] Verify notifications sent
- [ ] Test error handling (invalid data)
- [ ] Test rate limiting
- [ ] Verify logging/monitoring

### Test Environments

**Use separate test instances**:
- Test JIRA project (SOC-TEST)
- Test Slack channel (#soc-test)
- Test SIEM search head
- Mock data for testing

**Never test in production!**

---

## Monitoring & Troubleshooting

### Monitor Integration Health

**Track**:
- Webhook success rate
- API error rates
- Alert creation lag time
- Failed integrations
- Duplicate ticket creation

**Set up alerts**:
- Integration failure
- API rate limit hit
- Authentication failures
- Data quality issues

### Troubleshooting

**Common Issues**:

1. **Authentication failures**
   - Verify API token valid
   - Check token permissions
   - Verify user account active

2. **Field mapping errors**
   - Verify custom field IDs
   - Check required vs optional fields
   - Validate field value formats

3. **Webhook timeouts**
   - Check network connectivity
   - Verify JIRA instance reachable
   - Review payload size

4. **Duplicate tickets**
   - Implement deduplication logic
   - Check for existing issues before creating
   - Use unique identifiers

**Debug Mode**:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# JIRA library will log all API calls
```

---

## Integration Examples Repository

See `/integrations/examples/` for:
- Sample scripts
- Webhook payloads
- Configuration templates
- Testing utilities

---

## Support

Integration questions:
- SOC Team Lead: [contact]
- JIRA Administrator: [contact]
- IT Integration Team: [contact]

---

**Version**: 1.0
**Last Updated**: 2025-12-14
**Maintained By**: SOC Operations Team
