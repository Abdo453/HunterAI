---
name: "analyzing-office365-audit-logs-for-compromise"
description: "Parse Office 365 Unified Audit Logs via Microsoft Graph API to detect"
---

# Analyzing Office365 Audit Logs For Compromise

*Sourced from razor25000-cybersecurityskills*

# Analyzing Office 365 Audit Logs for Compromise

## Overview

Business Email Compromise (BEC) attacks often leave traces in Office 365 audit logs: suspicious inbox rule creation, email forwarding to external addresses, mailbox delegation changes, and unauthorized OAuth application consent grants. This skill uses the Microsoft Graph API to query the Unified Audit Log, enumerate inbox rules across mailboxes, detect forwarding configurations, and identify compromised account indicators.


## When to Use

- When a CLOUD security alert triggers and you need structured investigation steps
- When performing a cloud infrastructure review before a compliance audit (SOC 2, ISO 27001)
- When investigating unusual API calls, privilege escalation attempts, or resource modifications
- When a new workload is deployed and needs a security posture baseline before going to production
- When building detection rules for cloud-native SIEM (Sentinel, Security Hub, Chronicle)
- When a penetration tester identifies a misconfiguration and you need to scope the blast radius

## Prerequisites

- Azure AD app registration with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read` (application permissions)
- Python 3.9+ with `msal`, `requests`
- Client secret or certificate for authentication
- Global Reader or Security Reader role

## Steps

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Query Unified Audit Log for suspicious operations (Set-Mailbox, New-InboxRule)
3. Enumerate inbox rules across mailboxes and flag forwarding rules
4. Detect mailbox delegation changes (Add-MailboxPermission)
5. Identify OAuth consent grants to suspicious applications
6. Check for suspicious sign-in patterns from audit logs
7. Generate compromise indicator report with timeline

## Expected Output

- JSON report listing forwarding rules, delegation changes, OAuth grants, and suspicious audit events with risk scores
- Timeline of compromise indicators with affected mailboxes

