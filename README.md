# Microsoft Sentinel SOAR Lab: Brute Force Detection & Automated Email Response

**Author:** Pulkit Rai  
**Lab Environment:** Microsoft Azure  
**Platform:** Microsoft Sentinel (SIEM + SOAR)  
**Report Date:** May 2025  
**Classification:** Portfolio / Learning Lab

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Environment & Resources](#environment--resources)
4. [Step-by-Step Build Walkthrough](#step-by-step-build-walkthrough)
5. [KQL Analytics Rule](#kql-analytics-rule)
6. [Playbook & Automation Rule Configuration](#playbook--automation-rule-configuration)
7. [End-to-End Incident Flow](#end-to-end-incident-flow)
8. [Testing Procedure](#testing-procedure)
9. [Lessons Learned & Best Practices](#lessons-learned--best-practices)
10. [Future Improvements](#future-improvements)

---

## Executive Summary

This lab demonstrates the design and implementation of a cloud-native **Security Information and Event Management (SIEM)** and **Security Orchestration, Automation, and Response (SOAR)** solution using **Microsoft Sentinel** on Azure.

The primary objective was to simulate a realistic enterprise security operations workflow: detect a brute force attack in real time and automatically notify the security team via email — all without manual intervention.

### What Was Built

| Component | Technology |
|---|---|
| SIEM Platform | Microsoft Sentinel |
| Log Analytics Workspace | Azure Log Analytics |
| Virtual Machines (targets) | Ubuntu 24.04 + Windows Server 2022 |
| Log Collection | Azure Monitor Agent (AMA) + Data Collection Rules (DCR) |
| Detection Rule | Custom KQL Analytics Rule |
| Automated Response | Logic App (Playbook) + Automation Rule |
| Notification Channel | Office 365 Outlook (email) |

### Key Outcomes

- **Real-time detection** of brute force attacks (5+ failed logins in 1 minute) across both Linux and Windows VMs.
- **Automated incident creation** in Microsoft Sentinel upon threshold breach.
- **Zero-touch email alerting** dispatched to the security team the moment an incident is raised.
- Demonstrated the complete **alert → incident → response** pipeline using native Azure tooling.

---

## Architecture Overview

The following text-based diagram illustrates the high-level architecture of the lab environment and the automated incident response flow:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AZURE SUBSCRIPTION                           │
│                   Resource Group: sentinel-learning-ws              │
│                                                                     │
│  ┌─────────────────────┐       ┌──────────────────────────────┐    │
│  │   Virtual Machines   │       │   Log Analytics Workspace    │    │
│  │                      │       │   (sentinel-learning-ws)     │    │
│  │  ┌───────────────┐   │  AMA  │                              │    │
│  │  │ vm-linux-01   │───┼──────►│  Security Events (4625)      │    │
│  │  │ (Ubuntu 24.04)│   │  DCR  │  Syslog                      │    │
│  │  └───────────────┘   │       │  System / Application Logs   │    │
│  │                      │       │                              │    │
│  │  ┌───────────────┐   │  AMA  │                              │    │
│  │  │ vm-windows-01 │───┼──────►│                              │    │
│  │  │(Windows Server│   │  DCR  │                              │    │
│  │  └───────────────┘   │       └──────────────┬───────────────┘    │
│  └─────────────────────┘                       │                    │
│                                                │ KQL Query          │
│                                                ▼ (every 1 min)      │
│                                  ┌─────────────────────────┐        │
│                                  │   Microsoft Sentinel     │        │
│                                  │                          │        │
│                                  │  Analytics Rule:         │        │
│                                  │  "Brute Force – 5 Failed │        │
│                                  │   Logins in 1 Minute"   │        │
│                                  │                          │        │
│                                  │  Severity: HIGH          │        │
│                                  └────────────┬─────────────┘        │
│                                               │ Incident Created     │
│                                               ▼                      │
│                                  ┌─────────────────────────┐        │
│                                  │   Automation Rule        │        │
│                                  │   (Incident Trigger)     │        │
│                                  └────────────┬─────────────┘        │
│                                               │ Triggers Playbook    │
│                                               ▼                      │
│                                  ┌─────────────────────────┐        │
│                                  │  Logic App (Playbook)    │        │
│                                  │  BruteForce-Email-Alert  │        │
│                                  └────────────┬─────────────┘        │
│                                               │ Send Email           │
│                                               ▼                      │
│                                  ┌─────────────────────────┐        │
│                                  │   Office 365 Outlook     │        │
│                                  │   Security Team Email    │        │
│                                  └─────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────┘
```

**Data Flow Summary:**
1. Azure Monitor Agent collects Security/Syslog events from both VMs.
2. Data Collection Rules (DCR) forward logs to the Log Analytics Workspace.
3. Microsoft Sentinel runs a scheduled KQL query every minute.
4. If 5+ failed logins (EventID 4625 on Windows / SSH failures on Linux) are detected, an incident is created.
5. An Automation Rule triggers the Logic App Playbook.
6. The Playbook sends an automated email alert to the security team.

---

## Environment & Resources

### Azure Resource Summary

| Resource | Type | Details |
|---|---|---|
| `sentinel-learning-ws` | Resource Group | Contains all lab resources |
| `sentinel-learning-ws` | Log Analytics Workspace | Central log repository |
| Microsoft Sentinel | SIEM/SOAR Platform | Enabled on the workspace |
| `vm-linux-01` | Virtual Machine | Ubuntu 24.04 LTS |
| `vm-windows-01` | Virtual Machine | Windows Server 2022 |
| Azure Monitor Agent | Extension | Installed on both VMs |
| Data Collection Rule | DCR | Collects Security, System, Application, Syslog |
| `BruteForce-Email-Alert` | Logic App | SOAR Playbook for email notification |

### Log Sources Configured

| Log Type | Platform | Table in Sentinel |
|---|---|---|
| Security Events (EventID 4625) | Windows | `SecurityEvent` |
| Syslog (auth/ssh failures) | Linux | `Syslog` |
| System Logs | Windows | `Event` |
| Application Logs | Windows | `Event` |

---

## Step-by-Step Build Walkthrough

### Step 1 — Create the Resource Group

A dedicated resource group `sentinel-learning-ws` was created in the desired Azure region to contain all lab resources and simplify access management and cleanup.

### Step 2 — Deploy the Log Analytics Workspace

A Log Analytics Workspace named `sentinel-learning-ws` was provisioned. This serves as the central data store for all log ingestion and is the backend for Microsoft Sentinel.

### Step 3 — Enable Microsoft Sentinel

Microsoft Sentinel was added to the Log Analytics Workspace. This transforms the workspace into a full SIEM platform capable of:
- Collecting logs from connected data sources
- Running analytics rules (threat detections)
- Creating and managing incidents
- Executing automated playbooks

### Step 4 — Deploy Virtual Machines

Two virtual machines were deployed to act as monitored targets:

**vm-linux-01 (Ubuntu 24.04 LTS)**
- Represents a typical Linux server workload
- SSH authentication logs forwarded via Syslog

**vm-windows-01 (Windows Server)**
- Represents a Windows-based workload
- Windows Security Event logs (including failed login EventID 4625) forwarded via the Security Events data connector

### Step 5 — Install Azure Monitor Agent & Configure Data Collection Rules

The **Azure Monitor Agent (AMA)** was installed on both virtual machines as a VM extension. A **Data Collection Rule (DCR)** was configured to collect the following log streams and forward them to the Log Analytics Workspace:

- **Security Events** — Windows failed login attempts (EventID 4625)
- **System Logs** — Windows System event log
- **Application Logs** — Windows Application event log
- **Syslog** — Linux authentication messages (auth, authpriv facilities)

### Step 6 — Create the Analytics Rule

A custom Scheduled Analytics Rule was created in Microsoft Sentinel:

- **Name:** Brute Force - 5 Failed Logins in 1 Minute
- **Severity:** High
- **Query Frequency:** Every 1 minute
- **Query Period:** Last 1 minute
- **Trigger Threshold:** Alert when results ≥ 1 (grouped by source account/computer)

See [KQL Analytics Rule](#kql-analytics-rule) section for the full query.

### Step 7 — Create the Logic App Playbook

A Logic App named **BruteForce-Email-Alert** was created as the SOAR Playbook:

- **Trigger:** Microsoft Sentinel Incident — "When a Microsoft Sentinel incident is created or updated"
- **Action:** Send an email via Office 365 Outlook connector with incident details
- **Authentication:** Managed Identity / OAuth2 connection to Office 365

### Step 8 — Create the Automation Rule

An Automation Rule was configured in Microsoft Sentinel to link the Analytics Rule to the Playbook:

- **Trigger:** When incident is created
- **Condition:** Analytics Rule name contains "Brute Force"
- **Action:** Run Playbook → `BruteForce-Email-Alert`

---

## KQL Analytics Rule

The following KQL (Kusto Query Language) query is used in the Scheduled Analytics Rule to detect brute force login attempts on both Windows and Linux systems.

### Windows Brute Force Detection (EventID 4625)

```kql
// Detect 5 or more failed Windows login attempts within a 1-minute window
SecurityEvent
| where TimeGenerated >= ago(1m)
| where EventID == 4625                          // Windows failed login event
| where AccountType == "User"                    // Focus on user accounts
| summarize
    FailedLoginCount = count(),
    TargetAccounts   = make_set(TargetUserName),
    SourceIPs        = make_set(IpAddress)
    by
    Computer,
    bin(TimeGenerated, 1m)
| where FailedLoginCount >= 5                    // Threshold: 5+ failures in 1 minute
| extend
    AlertDetail = strcat(
        "Brute force detected on ", Computer,
        " — ", tostring(FailedLoginCount), " failed logins in 1 minute."
    )
| project
    TimeGenerated,
    Computer,
    FailedLoginCount,
    TargetAccounts,
    SourceIPs,
    AlertDetail
```

### Linux Brute Force Detection (Syslog)

```kql
// Detect 5 or more failed SSH login attempts on Linux within a 1-minute window
Syslog
| where TimeGenerated >= ago(1m)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"      // SSH failed authentication
| summarize
    FailedLoginCount = count(),
    SourceIPs        = make_set(extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage))
    by
    Computer,
    bin(TimeGenerated, 1m)
| where FailedLoginCount >= 5                    // Threshold: 5+ failures in 1 minute
| extend
    AlertDetail = strcat(
        "SSH brute force detected on ", Computer,
        " — ", tostring(FailedLoginCount), " failed login attempts in 1 minute."
    )
| project
    TimeGenerated,
    Computer,
    FailedLoginCount,
    SourceIPs,
    AlertDetail
```

### Rule Configuration Parameters

| Parameter | Value |
|---|---|
| Rule Name | Brute Force - 5 Failed Logins in 1 Minute |
| Rule Type | Scheduled |
| Severity | High |
| Query Frequency | Every 1 minute |
| Query Lookback Period | Last 1 minute |
| Alert Threshold | Generate alert when results ≥ 1 |
| Entity Mapping | Account → TargetUserName, Host → Computer, IP → IpAddress |
| Incident Creation | Enabled — group all alerts into a single incident |
| MITRE ATT&CK Tactic | Credential Access |
| MITRE ATT&CK Technique | T1110 — Brute Force |

---

## Playbook & Automation Rule Configuration

### Logic App Playbook: BruteForce-Email-Alert

The Logic App is the core SOAR component responsible for automated notification.

#### Trigger

```
Connector : Microsoft Sentinel
Trigger   : When a Microsoft Sentinel incident is created or updated
            (microsoft-sentinel-incident-trigger)
```

#### Actions (in order)

| Step | Action | Details |
|---|---|---|
| 1 | Parse Incident Details | Extract incident name, severity, description, and entity data from the trigger payload |
| 2 | Send an Email (V2) | Office 365 Outlook connector — compose and dispatch alert email |

#### Email Template

```
To      : security-team@organization.com
Subject : [HIGH ALERT] Brute Force Detected — {{Incident Title}}

Body:
─────────────────────────────────────────────
🚨 MICROSOFT SENTINEL SECURITY ALERT 🚨

Incident Name  : {{Incident Name}}
Severity       : {{Severity}}
Status         : {{Status}}
Created Time   : {{Created Time (UTC)}}
Incident URL   : {{Incident URL}}

Description:
{{Incident Description}}

Affected Entities:
{{Entities}}

Recommended Action:
1. Investigate the source IP address(es) immediately.
2. Review affected account(s) for signs of compromise.
3. Consider blocking the source IP at the NSG or firewall level.
4. Reset credentials for affected accounts if compromise is suspected.
─────────────────────────────────────────────
This is an automated notification from Microsoft Sentinel.
```

#### Required API Connections

| Connection | Type | Purpose |
|---|---|---|
| `azuresentinel` | Microsoft Sentinel | Read incident data |
| `office365` | Office 365 Outlook | Send email alerts |

#### Logic App — High-Level JSON Structure

```json
{
  "definition": {
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['azuresentinel']['connectionId']" } },
          "path": "/incident-creation"
        }
      }
    },
    "actions": {
      "Send_an_email_V2": {
        "type": "ApiConnection",
        "inputs": {
          "host": { "connection": { "name": "@parameters('$connections')['office365']['connectionId']" } },
          "method": "post",
          "path": "/v2/Mail",
          "body": {
            "To": "security-team@organization.com",
            "Subject": "[HIGH ALERT] @{triggerBody()?['object']?['properties']?['title']}",
            "Body": "<p>Incident: @{triggerBody()?['object']?['properties']?['title']}<br/>Severity: @{triggerBody()?['object']?['properties']?['severity']}</p>"
          }
        }
      }
    }
  }
}
```

---

### Automation Rule Configuration

The Automation Rule acts as the glue between the Analytics Rule (detection) and the Playbook (response).

| Field | Value |
|---|---|
| Rule Name | Run BruteForce-Email-Alert on Brute Force Incidents |
| Trigger | When incident is created |
| Condition — Analytics Rule Name | Contains "Brute Force" |
| Condition — Severity | Equals "High" |
| Action | Run Playbook: `BruteForce-Email-Alert` |
| Order | 1 (highest priority) |
| Status | Enabled |

---

## End-to-End Incident Flow

The following sequence describes the complete automated pipeline from attack to email alert:

```
 Attacker / Test Script
        │
        │  5+ failed login attempts within 60 seconds
        ▼
 ┌─────────────────┐
 │  vm-windows-01  │  EventID 4625 generated for each failed attempt
 │  vm-linux-01    │  Syslog "Failed password" message generated
 └────────┬────────┘
          │  Azure Monitor Agent (AMA)
          ▼
 ┌─────────────────────────────────┐
 │  Log Analytics Workspace         │
 │  Tables: SecurityEvent / Syslog  │
 └────────────────┬────────────────┘
                  │  Scheduled query runs every 1 minute
                  ▼
 ┌─────────────────────────────────┐
 │  Microsoft Sentinel              │
 │  Analytics Rule evaluation       │
 │  KQL: count(EventID 4625) >= 5   │
 └────────────────┬────────────────┘
                  │  Threshold breached → Alert fired
                  ▼
 ┌─────────────────────────────────┐
 │  Sentinel Incident Created       │
 │  Severity: HIGH                  │
 │  Status: New                     │
 └────────────────┬────────────────┘
                  │  Automation Rule matches incident
                  ▼
 ┌─────────────────────────────────┐
 │  Automation Rule                 │
 │  "Run BruteForce-Email-Alert"    │
 └────────────────┬────────────────┘
                  │  Playbook triggered
                  ▼
 ┌─────────────────────────────────┐
 │  Logic App: BruteForce-Email-Alert│
 │  Parses incident details         │
 │  Composes alert email            │
 └────────────────┬────────────────┘
                  │  Office 365 API call
                  ▼
 ┌─────────────────────────────────┐
 │  Security Team Email Inbox       │
 │  Subject: [HIGH ALERT] Brute ... │
 │  Body: Incident details + advice │
 └─────────────────────────────────┘

 Total pipeline latency: ~1–3 minutes from first failed login to email delivery
```

### Timeline Breakdown

| Stage | Approximate Latency |
|---|---|
| Log ingestion (AMA → Workspace) | ~30–60 seconds |
| Analytics Rule evaluation cycle | Every 60 seconds |
| Automation Rule + Playbook trigger | ~10–30 seconds |
| Email delivery (Office 365) | ~5–15 seconds |
| **Total end-to-end** | **~1.5 – 3 minutes** |

---

## Testing Procedure

### Prerequisites

- Both VMs are running and connected to Microsoft Sentinel
- Logs are flowing into the Log Analytics Workspace (verified in Logs blade)
- The Analytics Rule is active and enabled
- The Automation Rule is enabled and mapped to the correct Playbook
- The Logic App Playbook has valid API connections (Sentinel + Office 365)

---

### Test 1 — Windows Brute Force Simulation

**Objective:** Trigger EventID 4625 five or more times within 60 seconds on `vm-windows-01`.

**Method — PowerShell script (run on vm-windows-01 or a remote attacker machine):**

```powershell
# Simulate 10 failed Windows login attempts in rapid succession
$target   = "vm-windows-01"
$username = "fakeuser"
$password = ConvertTo-SecureString "WrongPassword123" -AsPlainText -Force
$cred     = New-Object System.Management.Automation.PSCredential($username, $password)

1..10 | ForEach-Object {
    try {
        Start-Process -FilePath "net" -ArgumentList "use \\$target\IPC$ /user:$username WrongPassword123" -Wait
    } catch {
        Write-Host "Attempt $_: failed (expected)"
    }
    Start-Sleep -Milliseconds 500
}
```

**Alternatively — using built-in Windows tools:**

```powershell
# Trigger failed logon events directly via runas (each attempt generates EventID 4625)
1..10 | ForEach-Object {
    Start-Process "runas" -ArgumentList '/user:.\fakeadmin "cmd /c exit"' -RedirectStandardInput "NUL" -Wait
    Start-Sleep -Milliseconds 300
}
```

**Expected Result:** EventID 4625 appears in `SecurityEvent` table; Sentinel incident created within ~2 minutes.

---

### Test 2 — Linux SSH Brute Force Simulation

**Objective:** Generate 5+ SSH failed login events on `vm-linux-01` within 60 seconds.

**Method — from an attacker machine (Linux/macOS terminal):**

```bash
# Simulate rapid SSH brute force (use a non-existent username to avoid account lockout)
TARGET_IP="<vm-linux-01-public-ip>"
USERNAME="fakeuser"

for i in $(seq 1 10); do
    ssh -o ConnectTimeout=3 \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        ${USERNAME}@${TARGET_IP} 2>/dev/null
    echo "Attempt $i sent"
    sleep 0.5
done
```

**Using `hydra` (if installed, for realistic simulation only in controlled lab):**

```bash
hydra -l fakeuser -P /usr/share/wordlists/rockyou.txt \
      -t 4 -V ssh://<vm-linux-01-public-ip>
```

> ⚠️ **Warning:** Only perform these tests against VMs you own and control. Never test against systems without explicit authorisation.

**Expected Result:** `Syslog` table shows "Failed password" messages; Sentinel incident created within ~2 minutes.

---

### Test 3 — Verify Log Ingestion (KQL Validation)

Run the following queries in the Microsoft Sentinel **Logs** blade to confirm data is flowing:

```kql
// Verify Windows failed login events
SecurityEvent
| where TimeGenerated > ago(10m)
| where EventID == 4625
| project TimeGenerated, Computer, TargetUserName, IpAddress
| order by TimeGenerated desc
```

```kql
// Verify Linux SSH failures
Syslog
| where TimeGenerated > ago(10m)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

---

### Test 4 — Verify Incident Creation

1. Navigate to **Microsoft Sentinel → Incidents**
2. Filter by **Severity: High** and **Status: New**
3. Confirm an incident titled **"Brute Force - 5 Failed Logins in 1 Minute"** has been created
4. Open the incident and review:
   - Mapped entities (Account, Host, IP)
   - Evidence (linked alerts and events)
   - Incident timeline

---

### Test 5 — Verify Playbook Execution

1. Navigate to **Microsoft Sentinel → Automation → Playbook runs** (or open the Logic App in Azure Portal)
2. Confirm the Logic App run was triggered successfully
3. Review the Logic App run history — all steps should show green checkmarks
4. Check the target email inbox for the automated alert

---

### Expected Test Results Summary

| Test | Expected Outcome |
|---|---|
| Windows brute force simulation | EventID 4625 entries appear in `SecurityEvent` |
| Linux SSH simulation | "Failed password" entries appear in `Syslog` |
| Analytics Rule triggers | Sentinel incident created with High severity |
| Automation Rule fires | Logic App run initiated within seconds of incident creation |
| Email received | Alert email in security team inbox with full incident details |

---

## Lessons Learned & Best Practices

### 1. Data Ingestion Latency Matters

Log ingestion from Azure Monitor Agent to Log Analytics has an inherent delay of 30–90 seconds. When setting alert thresholds and query frequencies, account for this latency to avoid missed detections or false negatives immediately after an attack begins.

**Best Practice:** Set the query lookback period slightly longer than the query frequency (e.g., 5-minute lookback with a 1-minute frequency) to ensure no events are missed between evaluation windows.

---

### 2. Azure Monitor Agent is the Modern Standard

The legacy Log Analytics Agent (MMA) is deprecated. Using the **Azure Monitor Agent (AMA) with Data Collection Rules (DCR)** provides:
- Granular control over which log streams are collected
- Cost optimisation (collect only what you need)
- Support for multiple workspaces from a single agent
- Built-in compliance with Azure Policy

---

### 3. KQL Proficiency is Essential for SOC Work

Writing effective KQL queries is the core skill for a Microsoft Sentinel engineer. Key lessons:
- Use `bin()` for time-window aggregations to group events correctly
- Use `make_set()` to aggregate multiple attacker IPs or targeted accounts
- Use `extend` to create readable alert descriptions embedded in the alert
- Always test KQL in the **Logs** blade before deploying to an Analytics Rule

---

### 4. Playbook Authentication Requires Careful Setup

Logic App API connections (especially Office 365 and Sentinel) require proper authentication:
- Use **Managed Identity** wherever possible to avoid storing credentials
- Grant the Logic App the **Microsoft Sentinel Responder** role on the workspace
- Test the Logic App manually using the "Run Trigger" feature before relying on automation

---

### 5. Automation Rules Provide Centralised Control

Rather than embedding automation logic in every Analytics Rule, Automation Rules act as a centralised policy layer:
- Multiple Analytics Rules can trigger the same Playbook
- Rules can set incident severity, assign owners, or add tags before running a Playbook
- Order/priority controls allow conditional logic across multiple rules

---

### 6. Cost Awareness in Learning Labs

Log Analytics data ingestion has a cost component. In a lab environment:
- Set short data retention periods (e.g., 30 days) to minimise storage costs
- Use DCR filters to avoid ingesting unnecessary verbose logs
- Use the Azure Pricing Calculator to estimate costs before scaling up

---

### 7. Least Privilege for Playbooks

The Logic App's Managed Identity should be granted only the minimum required permissions:
- `Microsoft Sentinel Responder` — to read incident data and update incidents
- Office 365 connection scoped to a dedicated shared mailbox (not a personal account)

---

## Future Improvements

The following enhancements would evolve this lab into a production-grade detection and response capability:

### 1. Automated IP Blocking via Network Security Groups

```
Playbook Enhancement:
  ┌─────────────────────┐
  │ Extract attacker IP  │
  │ from incident entity │
  └──────────┬──────────┘
             │
             ▼
  ┌─────────────────────┐
  │ Azure NSG Connector  │
  │ Add Deny Inbound Rule│
  │ for attacker IP      │
  └─────────────────────┘
```

Add an Azure Resource Manager action in the Logic App to automatically add a **Deny** rule to the VM's Network Security Group for the attacking IP address.

---

### 2. Microsoft Teams Notification

Replace or complement the email notification with a **Microsoft Teams** channel alert using the Teams connector in Logic Apps. This enables faster response for SOC teams actively monitoring Teams channels.

```json
{
  "type": "ApiConnection",
  "inputs": {
    "host": { "connection": { "name": "@parameters('$connections')['teams']['connectionId']" } },
    "method": "post",
    "path": "/v3/beta/teams/@{encodeURIComponent('SOC-Alerts-Channel')}/messages",
    "body": {
      "body": { "content": "🚨 Brute Force Detected! Incident: @{triggerBody()?['object']?['properties']?['title']}" }
    }
  }
}
```

---

### 3. Automated Account Disable via Microsoft Entra ID

For confirmed brute force incidents, automatically disable the targeted user account in **Microsoft Entra ID (Azure AD)** using the Azure AD Graph API connector:

```
Playbook Enhancement Flow:
  Incident Created
       │
       ▼
  Extract compromised username from entities
       │
       ▼
  Entra ID: Set user account → Disabled
       │
       ▼
  Add comment to Sentinel incident: "Account disabled automatically"
       │
       ▼
  Send email notification with account disable confirmation
```

---

### 4. Threat Intelligence Enrichment

Integrate **Microsoft Defender Threat Intelligence** or a third-party TI feed (e.g., VirusTotal, AbuseIPDB) to enrich incidents with reputation data for attacking IP addresses before sending the alert email.

---

### 5. Watchlist-Based Allow-Listing

Create a **Microsoft Sentinel Watchlist** of trusted IP ranges (e.g., corporate VPN, office egress IPs) and update the KQL query to exclude these IPs from brute force detection:

```kql
let TrustedIPs = (_GetWatchlist('TrustedIPRanges') | project SearchKey);
SecurityEvent
| where TimeGenerated >= ago(1m)
| where EventID == 4625
| where IpAddress !in (TrustedIPs)    // Exclude trusted sources
| summarize FailedLoginCount = count() by Computer, bin(TimeGenerated, 1m)
| where FailedLoginCount >= 5
```

---

### 6. ServiceNow / Jira Ticket Creation

Integrate the Playbook with **ServiceNow** or **Jira** to automatically create a ticket in the organization's ITSM platform, ensuring incident tracking and SLA management.

---

### 7. Multi-Stage Detection (Attack Chain)

Expand detection beyond a single brute force rule by building a **multi-stage attack chain** detection:
- Stage 1: Brute force attempt detected
- Stage 2: Successful login after brute force (lateral movement indicator)
- Stage 3: Privilege escalation or data exfiltration activity

Use **Fusion Rules** in Microsoft Sentinel to correlate these stages into a single high-confidence incident.

---

### 8. Sentinel UEBA Integration

Enable **User and Entity Behaviour Analytics (UEBA)** in Microsoft Sentinel to baseline normal login behaviour per user and machine. UEBA can reduce false positives and detect anomalies that a simple threshold rule would miss.

---

## Summary

This lab successfully demonstrates a complete cloud-native SIEM and SOAR pipeline:

| Capability | Status |
|---|---|
| Log collection from Linux and Windows VMs | ✅ Implemented |
| Real-time brute force detection via KQL | ✅ Implemented |
| Automated incident creation in Sentinel | ✅ Implemented |
| Zero-touch email alerting via Logic App | ✅ Implemented |
| End-to-end pipeline tested and verified | ✅ Implemented |

This environment provides a strong foundation for learning Microsoft Sentinel, practising KQL threat hunting, and understanding cloud-native security automation principles applicable to real-world SOC environments.

---

*Report generated as part of a Microsoft Sentinel SOAR learning lab. All testing was performed in an isolated Azure environment with no production systems involved.*
