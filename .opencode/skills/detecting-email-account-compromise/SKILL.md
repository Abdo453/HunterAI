---
name: "detecting-email-account-compromise"
description: "Detect compromised O365 and Google Workspace email accounts by analyzing"
---

# Detecting Email Account Compromise

*Sourced from razor25000-cybersecurityskills*

# Detecting Email Account Compromise

## Overview

Email account compromise (EAC) is a prevalent attack vector where adversaries gain unauthorized access to mailboxes to exfiltrate sensitive data, conduct business email compromise (BEC), or establish persistence through inbox rule manipulation. Attackers commonly create forwarding rules to siphon emails, delete rules to hide evidence, or use OAuth tokens for persistent access. Detection relies on analyzing Microsoft 365 Unified Audit Logs, Azure AD sign-in logs for impossible travel or suspicious locations, inbox rule creation events (Set-InboxRule, New-InboxRule), and Microsoft Graph API access patterns. Key indicators include forwarding rules to external addresses, rules that delete or move messages matching keywords like "invoice" or "payment", and sign-ins from unusual user agents such as python-requests.


## When to Use

- When an incident is declared and the IR team needs a structured playbook to execute
- When a ransomware or data breach event requires immediate containment and scope definition
- When post-incident review identifies gaps in the existing IR runbook that need remediation
- When training junior analysts on incident handling procedures via tabletop exercises
- When regulatory timelines require documented response steps (GDPR 72h notification, etc.)
- When a threat actor is suspected to still be active and persistence mechanisms need identification

## Prerequisites

- Microsoft 365 with Unified Audit Logging enabled
- Azure AD P1/P2 for risk detection APIs
- Python 3.9+ with `requests`, `msal` libraries
- Microsoft Graph API application registration with Mail.Read, AuditLog.Read.All permissions
- Understanding of OAuth2 client credential flows

## Steps

1. Export audit logs or connect to Microsoft Graph API using MSAL authentication
2. Query inbox rules for all monitored mailboxes via `/users/{id}/mailFolders/inbox/messageRules`
3. Analyze rules for external forwarding (ForwardTo, RedirectTo external addresses)
4. Detect suspicious rule patterns: deletion rules, keyword-matching rules targeting financial terms
5. Query sign-in logs via `/auditLogs/signIns` for unusual locations and impossible travel
6. Check for suspicious user agent strings (python-requests, PowerShell, curl)
7. Identify OAuth application consent grants for suspicious third-party apps
8. Correlate findings across users to detect campaign-level compromise
9. Generate compromise indicators report with severity scores

## Expected Output

A JSON report listing compromised or suspicious accounts, malicious inbox rules detected, impossible travel events, suspicious OAuth grants, and recommended containment actions with severity ratings.

