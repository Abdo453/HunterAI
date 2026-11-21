---
name: "detecting-aws-iam-privilege-escalation"
description: "Detect AWS IAM privilege escalation paths using boto3 and Cloudsplaining"
---

# Detecting Aws Iam Privilege Escalation

*Sourced from razor25000-cybersecurityskills*

# Detecting AWS IAM Privilege Escalation

## Overview

This skill uses boto3 and Cloudsplaining-style analysis to identify IAM privilege escalation paths in AWS accounts. It downloads the account authorization details, analyzes each policy for dangerous permission combinations (iam:PassRole + lambda:CreateFunction, iam:CreatePolicyVersion, sts:AssumeRole), and flags policies that violate least-privilege principles.


## When to Use

- When a AWS security alert triggers and you need structured investigation steps
- When performing a cloud infrastructure review before a compliance audit (SOC 2, ISO 27001)
- When investigating unusual API calls, privilege escalation attempts, or resource modifications
- When a new workload is deployed and needs a security posture baseline before going to production
- When building detection rules for cloud-native SIEM (Sentinel, Security Hub, Chronicle)
- When a penetration tester identifies a misconfiguration and you need to scope the blast radius

## Prerequisites

- Python 3.8+ with boto3 library
- AWS credentials with IAM read-only access (iam:GetAccountAuthorizationDetails)
- Optional: cloudsplaining Python package for HTML report generation

## Steps

1. **Download IAM Authorization Details** — Call iam:GetAccountAuthorizationDetails to retrieve all users, groups, roles, and policies
2. **Analyze Policies for Privilege Escalation** — Check each policy for known escalation permission combinations
3. **Identify Wildcard Resource Policies** — Flag policies using Resource: "*" with dangerous actions
4. **Map Principal-to-Policy Relationships** — Build a graph of which principals can access which escalation paths
5. **Score and Prioritize Findings** — Rank findings by severity based on escalation vector type
6. **Generate Report** — Produce structured JSON report with remediation guidance

## Expected Output

- JSON report of privilege escalation findings with severity scores
- List of dangerous permission combinations per principal
- Wildcard resource policy audit results
- Remediation recommendations for each finding

