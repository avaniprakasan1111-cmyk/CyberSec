# Windows Fundamentals for SOC Analyst



### Goal

Understand the Windows identity, service, registry, scheduled task, Defender, Entra ID, Sentinel `SecurityEvent`, and Event Viewer fundamentals required for SOC L1 investigations.

---

## Topics Covered

| Topic | SOC Focus |
|---|---|
| Windows users and groups | Account creation, group membership, privilege changes |
| Local admin vs domain admin | Scope of compromise and privilege impact |
| Windows services | Persistence, remote execution, suspicious service paths |
| Windows registry | Configuration evidence and attacker persistence |
| Registry Run keys | Logon-based persistence |
| Scheduled tasks | Triggered or repeated malicious execution |
| Windows Defender telemetry | Malware detection and AV tampering |
| Microsoft Entra ID users/groups | Cloud identity and access control |
| SecurityEvent table | Sentinel Windows event investigation |
| Event Viewer | Local Windows log analysis practice |

---

## Important Windows Event IDs

| Event ID | Meaning | Why SOC Cares |
|---:|---|---|
| 4624 | Successful logon | Identify account, host, IP, and logon type |
| 4625 | Failed logon | Detect brute force, password spray, failed RDP |
| 4672 | Special privileges assigned | Admin or privileged logon indicator |
| 4688 | Process created | Detect suspicious tools and command line |
| 4697 | Service installed | Service-based persistence or execution |
| 4698 | Scheduled task created | Task-based persistence |
| 4702 | Scheduled task updated | Changed task action or trigger |
| 4720 | User created | Potential backdoor account |
| 4722 | User enabled | Re-enabled dormant account |
| 4726 | User deleted | Possible cleanup or admin action |
| 4728 | User added to global group | Possible domain privilege escalation |
| 4732 | User added to local group | Possible local admin escalation |
| 4740 | Account locked out | Password guessing or user issue |
| 1102 | Security audit log cleared | Possible anti-forensics |
| 1116 | Defender malware detected | Malware or PUA detection |
| 5001 | Defender real-time protection disabled | Possible defense evasion |
| 5007 | Defender configuration changed | Security setting changed |

---

## Table of Contents

1. [Windows Users and Groups](#1-windows-users-and-groups)
2. [Local Admin vs Domain Admin](#2-local-admin-vs-domain-admin)
3. [Windows Services](#3-windows-services)
4. [Windows Registry](#4-windows-registry-hklm-hkcu-hku-hkcr-hkcc)
5. [Registry Run Keys for Persistence](#5-registry-run-keys-for-persistence)
6. [Scheduled Tasks](#6-scheduled-tasks)
7. [Windows Defender Basic Telemetry](#7-windows-defender-basic-telemetry)
8. [Microsoft Entra ID Users and Groups](#8-azure-topic-microsoft-entra-id-users-and-groups)
9. [Sentinel SecurityEvent Table](#9-sentinel-topic-windows-securityevent-table)
10. [Event Viewer Practice](#10-tool-to-practise-event-viewer)
11. [Mini SOC Scenario](#mini-soc-scenario-suspicious-local-admin-added)
12. [Day 4 SOC Revision Checklist](#day-4-soc-revision-checklist)

---

# 1. Windows Users and Groups

A Windows user account is an identity used to log in, access files, run programs, and perform actions on a Windows system. A group is a collection of users used to assign permissions in a manageable way.

## User Types

| User Type | Meaning | SOC Relevance |
|---|---|---|
| Local user | Exists only on one computer | Check for attacker-created backdoor accounts |
| Domain user | Exists in Active Directory domain | Used across many company systems |
| Microsoft Entra ID user | Cloud identity for Azure and Microsoft 365 | Important for cloud login investigations |
| Service account | Used by applications or services | High risk if overprivileged or interactive login is allowed |

## Important Groups

| Group | Meaning | SOC Risk |
|---|---|---|
| Administrators | Full control on the machine | Very high risk |
| Remote Desktop Users | Can RDP into the machine | Useful for lateral movement |
| Backup Operators | Can back up/restore files | Can access sensitive data |
| Event Log Readers | Can read event logs | Useful but should be controlled |
| Users | Standard users | Normal low privilege |
| Guests | Limited guest access | Usually disabled |

## User and Group Event IDs

| Event ID | Meaning |
|---:|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4726 | User account deleted |
| 4732 | User added to local security group |
| 4733 | User removed from local security group |
| 4728 | User added to global security group |
| 4729 | User removed from global security group |
| 4740 | User account locked out |
| 4624 | Successful logon |
| 4625 | Failed logon |

## SOC Investigation Questions

1. Who made the account or group change?
2. Which account was created, enabled, deleted, or modified?
3. Was the account added to Administrators, Remote Desktop Users, Domain Admins, or another privileged group?
4. Was the action during business hours?
5. Was there a successful logon after the change?
6. Did the same account, host, or source IP perform other suspicious actions?

## Event Viewer Path

```text
eventvwr.msc
Windows Logs > Security
Filter Event IDs: 4720, 4722, 4726, 4732, 4733, 4728, 4729, 4740, 4624, 4625
```

---

# 2. Local Admin vs Domain Admin

A local administrator has full control over one machine. A domain administrator has administrative power across the Active Directory domain. In SOC investigations, this difference tells you the possible blast radius of the compromise.

| Area | Local Admin | Domain Admin |
|---|---|---|
| Scope | One machine | Entire domain |
| Risk level | High | Critical |
| Example attack | Disable AV or create local service | Create users, modify GPO, access many systems |
| Typical abuse | Dump local credentials, install tools | Domain takeover or large-scale lateral movement |

## Suspicious Signs

- Standard user added to local Administrators
- Unknown user added to Domain Admins or privileged group
- Local admin used for RDP logon
- Domain admin logging into a normal workstation
- Admin account used at unusual time
- Privilege change followed by service or scheduled task creation

## Simple Sentinel KQL

```kql
SecurityEvent
| where EventID in (4728, 4732)
| project TimeGenerated, Computer, Account, TargetAccount, Activity, EventID
| order by TimeGenerated desc
```

---

# 3. Windows Services

A Windows service is a background program that can run without a user manually opening it. Services are managed by the Service Control Manager and can run with powerful accounts such as `LocalSystem`.

| Service | Purpose |
|---|---|
| WinDefend | Microsoft Defender Antivirus |
| EventLog | Windows Event Log service |
| Spooler | Print service |
| W32Time | Windows time service |
| LanmanServer | File and printer sharing |

## SOC Importance

Attackers often create or modify services for persistence, privilege escalation, remote execution, and running malware after reboot.

## Service Fields to Check

| Field | Why It Matters |
|---|---|
| Service name | Is it known, random, or typo-squatting a real service? |
| Display name | Does it imitate Microsoft or security software? |
| Image path | Does the executable run from AppData, Temp, Public, or ProgramData? |
| Start type | Auto-start indicates persistence |
| Service account | LocalSystem is highly privileged |
| Created time | Compare with suspicious logon or malware alert time |

## Service Event IDs

| Event ID | Log | Meaning |
|---:|---|---|
| 4697 | Security | Service installed |
| 7045 | System | New service installed |
| 7036 | System | Service started/stopped |

## Suspicious Service Indicators

- Service path from `C:\Users`, `AppData`, `Temp`, `Public`, or `ProgramData`
- Service running `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`, or `regsvr32.exe`
- Random or misspelled service name such as `svhost.exe` instead of `svchost.exe`
- Service created shortly after suspicious login
- Service running as `LocalSystem` without clear business reason

## Sentinel KQL

```kql
SecurityEvent
| where EventID == 4697
| project TimeGenerated, Computer, Account, ServiceName, ServiceFileName, EventID
| order by TimeGenerated desc
```

---

# 4. Windows Registry: HKLM, HKCU, HKU, HKCR, HKCC

The Windows Registry is a database that stores operating system, user, application, service, startup, and security configuration. Attackers often use registry changes for persistence and defense evasion.

| Hive | Full Name | Meaning |
|---|---|---|
| HKLM | HKEY_LOCAL_MACHINE | Machine-wide settings |
| HKCU | HKEY_CURRENT_USER | Settings for current logged-in user |
| HKU | HKEY_USERS | Settings for all user profiles |
| HKCR | HKEY_CLASSES_ROOT | File associations and COM objects |
| HKCC | HKEY_CURRENT_CONFIG | Current hardware profile |

## SOC Meaning

| Hive | Scope | SOC Meaning |
|---|---|---|
| HKLM | Whole computer | Persistence or config change can affect all users |
| HKCU | Current user only | Persistence may trigger only when that user logs in |

## Useful Registry Tools

```text
regedit.exe
reg.exe
PowerShell Get-ItemProperty
Sysinternals Autoruns
```

Example command:

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

## SOC Warning

Registry changes are not always visible in normal Security logs by default. Better visibility usually requires registry auditing, Sysmon, EDR, or Defender for Endpoint telemetry.

---

# 5. Registry Run Keys for Persistence

Registry Run and RunOnce keys are common startup locations. Run keys execute programs when a user logs in. RunOnce keys normally execute once and then remove themselves.

| Run Key Path | Scope |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Current user persistence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Current user one-time execution |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Machine-wide persistence |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Machine-wide one-time execution |

## Example Malicious Run Key

```text
Name: WindowsUpdate
Data: powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1
```

## Suspicious Run Key Indicators

- Value points to `C:\Users`, `AppData`, `Public`, `Temp`, or `ProgramData`
- Value runs `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, or `regsvr32.exe`
- Value uses encoded PowerShell or hidden window execution
- Value name imitates Windows Update, OneDrive, Chrome, Adobe, or security tools

## Practical Checks

```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
```

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```

## Investigation Flow

1. Check value name and command
2. Check file path and file hash
3. Check file creation time
4. Check whether the file still exists
5. Check process execution logs around first run
6. Check user logon before and after persistence
7. Check Defender or EDR alerts for the same file
8. Escalate if unauthorized, unknown, or malicious

---

# 6. Scheduled Tasks

A scheduled task runs a program or command based on a trigger such as logon, startup, daily schedule, idle state, or a specific Windows event.

## Scheduled Task Event IDs

| Event ID | Meaning |
|---:|---|
| 4698 | Scheduled task created |
| 4699 | Scheduled task deleted |
| 4700 | Scheduled task enabled |
| 4701 | Scheduled task disabled |
| 4702 | Scheduled task updated |

## Event Viewer Paths

```text
Windows Logs > Security
Filter Event IDs: 4698, 4699, 4700, 4701, 4702

Applications and Services Logs > Microsoft > Windows > TaskScheduler > Operational
```

## Suspicious Scheduled Task Examples

- Task runs from AppData, Public, Temp, or ProgramData
- Task action runs encoded PowerShell or script interpreters
- Task name is random or imitates Microsoft/Adobe/Chrome updater
- Task created by a normal user but runs with high privilege
- Task runs as SYSTEM
- Task triggers at logon or startup
- Task created shortly after phishing, malware, or RDP activity

## Fields to Check

| Field | What to Ask |
|---|---|
| Task name | Legitimate or random? |
| Author | Which user created it? |
| Action | What command runs? |
| Trigger | When does it run? |
| Run as | User, admin, or SYSTEM? |
| Path | Trusted location or suspicious directory? |

## Sentinel KQL

```kql
SecurityEvent
| where EventID in (4698, 4699, 4700, 4701, 4702)
| project TimeGenerated, Computer, Account, EventID, Activity
| order by TimeGenerated desc
```

---

# 7. Windows Defender Basic Telemetry

Windows Defender telemetry helps the SOC understand malware detections, actions taken, failed remediation, and possible tampering with protection settings.

## Event Viewer Path

```text
Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational
```

## Defender Event IDs

| Event ID | Meaning | SOC Interpretation |
|---:|---|---|
| 1000 | Scan started | Normal scan activity |
| 1001 | Scan completed | Confirm scan finished |
| 1002 | Scan cancelled | Check if user/admin or attacker cancelled |
| 1116 | Malware detected | Check threat, file, user, path, and source |
| 1117 | Malware action taken | Confirm quarantine/remove succeeded |
| 1118 | Malware action failed | Escalate quickly |
| 1119 | Critical malware action failure | High severity review |
| 5001 | Real-time protection disabled | Possible defense evasion |
| 5004 | Real-time protection configuration changed | Validate approved change |
| 5007 | Defender configuration changed | Review unexpected security config changes |
| 5008 | Defender engine failure | Protection may be degraded |

## Key Investigation Questions

- What threat was detected?
- Where was the file located?
- Which user was logged in?
- Was the file quarantined, removed, allowed, or action failed?
- Did the malware execute before detection?
- Was Defender disabled before or after detection?
- Are there related process, network, logon, service, or task events?

## Common Suspicious Pattern

```text
4624 successful login
-> PowerShell execution
-> Defender config changed 5007
-> Real-time protection disabled 5001
-> Malware file appears
-> Scheduled task or service created
```

---

# 8. Azure Topic: Microsoft Entra ID Users and Groups

Microsoft Entra ID is Microsoft cloud identity. It manages users, groups, application access, roles, authentication, and cloud identity security for Azure and Microsoft 365 environments.

## User Types

| User Type | Meaning |
|---|---|
| Member user | Internal employee, student, or company user |
| Guest user | External user invited through B2B collaboration |
| Admin user | User assigned privileged Entra role |
| Service principal | Application identity used by software or automation |

## Group Types

| Group Type | Meaning |
|---|---|
| Security group | Used for access control |
| Microsoft 365 group | Used for collaboration such as Teams, SharePoint, mailbox |
| Dynamic group | Membership based on rules |
| Assigned group | Members added manually |

## SOC Risks in Entra Users/Groups

- New admin user created
- Guest user invited unexpectedly
- User added to privileged role
- User added to sensitive application group
- MFA disabled or authentication method changed
- Conditional Access policy changed
- Risky sign-in or impossible travel
- Password spray activity
- Account disabled or enabled unexpectedly

## Investigation Areas

| Investigation Area | What to Check |
|---|---|
| Sign-in logs | Who logged in, from where, device, app, result, MFA |
| Audit logs | Who changed users, groups, roles, apps, policies |
| Risky users | Identity Protection risk detections |
| Group membership | Privilege or sensitive app access changes |
| App assignments | Access to sensitive SaaS or Azure apps |
| Conditional Access | Policy changes and exclusions |

## Example SOC Scenario

Scenario:

```text
A normal user is added to a Global Administrator role or a privileged access group.
```

Investigation steps:

1. Check who added the user
2. Check source IP and location of the admin action
3. Confirm whether the change was approved
4. Review sign-ins before and after the change
5. Check whether MFA was satisfied
6. Check whether the account performed admin actions
7. Escalate if unauthorized or suspicious

---

# 9. Sentinel Topic: Windows SecurityEvent Table

In Microsoft Sentinel and Azure Monitor, the `SecurityEvent` table stores Windows security events collected from Windows machines. SOC analysts use this table to investigate logons, account changes, group changes, service installation, scheduled tasks, process creation, and audit log clearing.

## SecurityEvent Columns

| Column | Meaning |
|---|---|
| TimeGenerated | When the event happened |
| Computer | Host name |
| EventID | Windows event ID |
| Activity | Event description |
| Account | Account involved |
| TargetAccount | Target account |
| IpAddress | Source IP, when available |
| LogonType | Type of logon |
| Process | Process name, when available |
| CommandLine | Command line, if enabled |
| SubjectAccount | Account that performed the action |

## Useful KQL Examples

### Count events by Event ID

```kql
SecurityEvent
| summarize EventCount = count() by EventID, Activity
| order by EventCount desc
```

### Find failed logons

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedCount = count() by TargetAccount, Computer, IpAddress
| order by FailedCount desc
```

### Find successful admin logons

```kql
SecurityEvent
| where EventID == 4624
| where Account contains "admin"
| project TimeGenerated, Computer, Account, IpAddress, LogonType, Activity
| order by TimeGenerated desc
```

### Find newly created users

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, Account, TargetAccount, Activity
| order by TimeGenerated desc
```

### Find users added to local groups

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Computer, Account, TargetAccount, Activity
| order by TimeGenerated desc
```

### Find security log clearing

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
| order by TimeGenerated desc
```

---

# 10. Tool to Practise: Event Viewer

Event Viewer is the built-in Windows tool for viewing system, security, application, Defender, Task Scheduler, and PowerShell logs. It is very useful for learning Windows investigation before working in Sentinel.

## How to Open

```text
Press Windows + R
Type: eventvwr.msc
Press Enter
```

## Important Logs

| Log | Use |
|---|---|
| Security | Logons, account changes, group changes, audit events |
| System | Services, drivers, system startup/shutdown |
| Application | Application errors and crashes |
| Windows Defender Operational | Defender detections and configuration changes |
| TaskScheduler Operational | Scheduled task creation and execution |
| PowerShell Operational | PowerShell activity |

## Practice Exercises

| Exercise | Path / Event IDs | What to Check |
|---|---|---|
| Failed logons | Windows Logs > Security, Event ID 4625 | Account, source network address, logon type, failure reason, time |
| Successful logons | Windows Logs > Security, Event ID 4624 | Account, host, IP, logon type, time |
| User/group changes | Security, IDs 4720, 4722, 4726, 4732, 4733 | Who changed what, target group, business approval |
| Defender alerts | Defender Operational, IDs 1116, 1117, 5001, 5007 | Threat name, file path, action, status, user |
| Scheduled tasks | Security IDs 4698, 4702 and TaskScheduler Operational | Task name, action, trigger, run-as account |

## Logon Types

| Logon Type | Meaning |
|---:|---|
| 2 | Interactive keyboard login |
| 3 | Network login |
| 7 | Unlock |
| 10 | Remote Desktop |
| 11 | Cached domain logon |

---

# Mini SOC Scenario: Suspicious Local Admin Added

## Alert

```text
User added to local Administrators group on a workstation.
```

## Step 1 - Search Group Change

```kql
SecurityEvent
| where EventID == 4732
| project TimeGenerated, Computer, Account, TargetAccount, Activity
| order by TimeGenerated desc
```

## Step 2 - Check Successful Login After Group Change

```kql
SecurityEvent
| where EventID == 4624
| where TargetAccount contains "suspicioususer"
| project TimeGenerated, Computer, TargetAccount, IpAddress, LogonType
| order by TimeGenerated desc
```

## Step 3 - Check Persistence

```kql
SecurityEvent
| where EventID in (4697, 4698, 4702)
| project TimeGenerated, Computer, Account, EventID, Activity
| order by TimeGenerated desc
```

## Step 4 - Check Audit Log Clearing

```kql
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account, Activity
| order by TimeGenerated desc
```

## Suspicious Verdict If

- User was added by unknown or compromised account
- Action happened outside business hours
- User logged in through RDP after privilege change
- Service or scheduled task was created after the privilege change
- Defender was disabled or configuration changed
- Security audit log was cleared

---

# Day 4 SOC Revision Checklist

| Question | Answer to Remember |
|---|---|
| What event means successful logon? | 4624 |
| What event means failed logon? | 4625 |
| What event means user created? | 4720 |
| What event means user added to local group? | 4732 |
| What event means scheduled task created? | 4698 |
| What event means service installed? | 4697 or System 7045 |
| What event means Security log cleared? | 1102 |
| Where are Defender events? | Windows Defender > Operational |
| Where are Run keys? | HKCU/HKLM `Software\Microsoft\Windows\CurrentVersion\Run` |
| What Sentinel table stores Windows Security logs? | SecurityEvent |

---

## Final Note

Event availability depends on audit policy, data connector settings, Sysmon/EDR deployment, and Windows version. Always correlate with endpoint, identity, network, and Defender telemetry where available.

---

## Author

**Avani Prakasan**  
SOC Analyst Learning Journey  

