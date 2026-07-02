# Windows Event IDs

Printable SOC study notes for **Windows Security logs**, **Microsoft Entra ID sign-in logs**, and **Microsoft Sentinel KQL basics**.

Use this note to understand what each event means, which fields to check during investigation, what normal activity can look like, and which patterns may indicate brute-force, lateral movement, persistence, account compromise, or suspicious administrative activity.

---

## Quick Reference

| Topic | Meaning | SOC Use |
|---|---|---|
| **4624** | Successful logon | Check who logged in, from where, when, and using which logon type. |
| **4625** | Failed logon | Detect brute-force, password spraying, invalid credentials, and account lockout patterns. |
| **4688** | Process creation | Investigate commands, scripts, parent-child process relationships, and malware execution. |
| **4697** | Service installed | Detect service-based persistence or suspicious service installation. |
| **7045** | New service created | System log evidence that a service was installed by Service Control Manager. |
| **4776** | NTLM authentication | Track NTLM credential validation, especially failures and lateral movement attempts. |
| **4720** | User account created | Detect suspicious new local or domain accounts. |
| **Logon Types 2, 3, 7, 10** | How the logon happened | Identify local login, network login, unlock, or RDP access. |
| **Entra ID Sign-in Logs** | Cloud identity authentication logs | Investigate Azure/Microsoft 365 sign-ins, MFA, location, app access, and risk. |
| **Sentinel KQL** | Query language for log investigation | Search failed logins, group by IP/user, and identify attack patterns. |

---

## 1. Event ID 4624 - Successful Logon

Event ID **4624** means a user, computer, or service successfully logged on to a Windows system. This event is generated on the destination machine where the logon session was created.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **TargetUserName / Account** | The user account that successfully logged in. |
| **LogonType** | How the logon happened, such as local, network, unlock, or RDP. |
| **IpAddress / Source Network Address** | The source IP address of the login attempt, if available. |
| **WorkstationName** | The source computer name. |
| **AuthenticationPackageName** | Authentication method, such as Kerberos or NTLM. |
| **LogonID** | Unique logon session ID. Useful for correlating with later events. |
| **ProcessName** | Process involved in the logon. |

### Normal vs Suspicious Examples

| Normal Example | Suspicious Example |
|---|---|
| Employee logs into their laptop during working hours. | Admin account logs into a normal workstation without business reason. |
| Administrator connects to a server through approved RDP. | Successful RDP logon from an unknown IP after many failed attempts. |
| Service account authenticates from its expected server. | Service account logs in interactively or from an unusual machine. |

> **SOC Tip:** A successful login does not automatically mean safe activity. Always check the user, source, device, time, logon type, and whether the account normally performs that action.

---

## 2. Event ID 4625 - Failed Logon

Event ID **4625** means a user or system failed to log on. One failed attempt can be normal, but repeated failures can indicate brute-force, password spraying, credential stuffing, or a misconfigured service.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **TargetUserName / Account** | The account that failed to log in. |
| **LogonType** | The login method attempted. |
| **FailureReason** | Human-readable reason for failure. |
| **Status / SubStatus** | Technical failure code, useful for precise diagnosis. |
| **IpAddress** | Source IP address. |
| **WorkstationName** | Source workstation name. |
| **ProcessName** | Process that triggered the attempt. |

### Patterns to Investigate

| Pattern | Possible Meaning |
|---|---|
| Many failures against one account | Possible brute-force attack against that account. |
| One IP failing against many users | Possible password spraying. |
| Failed RDP logons | Possible RDP attack or exposed remote access. |
| Failures followed by Event ID 4624 | Possible successful compromise after guessing password. |
| Failures for disabled or old accounts | Attack using old credentials or misconfigured service. |

---

## 3. Event ID 4688 - Process Creation

Event ID **4688** means a new process was created. This is one of the most important Windows events for malware analysis, endpoint investigation, and attacker behavior tracking.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **NewProcessName** | The executable that started. |
| **CommandLine** | The full command used, if command-line auditing is enabled. |
| **ParentProcessName** | The process that launched the new process. |
| **SubjectUserName** | The user context used to run the process. |
| **ProcessId** | The process identifier. |
| **CreatorProcessId** | The parent process identifier. |

### Suspicious Process Behavior

| Suspicious Process or Behavior | Why It Matters |
|---|---|
| `powershell.exe -enc` | Encoded PowerShell is often used to hide malicious commands. |
| `cmd.exe /c whoami` | Common attacker reconnaissance. |
| `net user`, `net group`, `nltest`, `dsquery` | User, group, and domain discovery. |
| `rundll32.exe` or `regsvr32.exe` abuse | Living-off-the-land technique to run malicious code. |
| Office application spawning PowerShell | Possible malicious macro or document-based attack. |
| Browser spawning `cmd.exe` | Possible exploit, malicious download, or script execution. |

> **SOC Tip:** Parent-child process relationship is very important. For example, `winword.exe -> powershell.exe` is more suspicious than `explorer.exe -> notepad.exe`.

---

## 4. Event ID 4697 - Service Installed

Event ID **4697** means a new Windows service was installed. Attackers commonly create services for persistence, privilege execution, or lateral movement.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **ServiceName** | Name of the installed service. |
| **ServiceFileName** | Executable path for the service. |
| **ServiceType** | Service or driver type. |
| **ServiceStartType** | Whether it starts automatically, manually, or is disabled. |
| **SubjectUserName** | Account that installed the service. |

### Suspicious Signs

| Suspicious Sign | Possible Meaning |
|---|---|
| Service path in `C:\Users\Public` or `Temp` | Malware or unauthorized tool running from a suspicious location. |
| Random-looking service name | Possible attacker-created persistence. |
| Service running `powershell.exe` or `cmd.exe` | Highly suspicious execution method. |
| Service installed by normal user | Possible privilege misuse or compromised account. |
| Auto-start service after compromise | Persistence after reboot. |

---

## 5. Event ID 7045 - New Service Created

Event ID **7045** also shows that a new service was installed, but it usually appears in the **System log** from **Service Control Manager**. In investigations, check both **4697** and **7045** because visibility depends on audit and log collection settings.

### 4697 vs 7045

| Event ID | Typical Log | Meaning |
|---|---|---|
| **4697** | Security log | A service was installed, based on security audit policy. |
| **7045** | System log | Service Control Manager recorded a new service installation. |

### Suspicious Signs

| Suspicious Sign | Why It Matters |
|---|---|
| Remote service creation | Can indicate lateral movement. |
| Service using `ADMIN$` or remote path | Common with tools such as PsExec-style execution. |
| Service starts automatically | May allow persistence after restart. |
| Service executable in user profile folder | Unusual location for legitimate services. |

---

## 6. Event ID 4776 - NTLM Authentication

Event ID **4776** is generated when credentials are validated using **NTLM authentication**. For domain accounts, it is commonly seen on the domain controller. For local accounts, it may appear on the local computer.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **AccountName** | The account being authenticated. |
| **Workstation** | The source computer that made the request. |
| **Status** | Whether authentication succeeded or failed. |
| **AuthenticationPackage** | Usually NTLM. |

### Patterns to Investigate

| Pattern | Possible Meaning |
|---|---|
| Many failed NTLM attempts | Password spraying or brute-force. |
| NTLM from unusual workstation | Compromised machine or unexpected legacy authentication. |
| Admin account authenticating using NTLM | Possible lateral movement or weak configuration. |
| Repeated NTLM failures causing lockout | Wrong saved password, old service credentials, or attack. |
| NTLM where Kerberos is expected | Misconfiguration or suspicious fallback behavior. |

---

## 7. Event ID 4720 - User Account Created

Event ID **4720** means a new user account was created. This can be normal during onboarding, but attackers may create accounts to maintain access after compromise.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **SubjectAccountName** | Who created the account. |
| **TargetUserName / NewAccountName** | The newly created user account. |
| **TargetDomainName** | Domain or local computer where account was created. |
| **SecurityID** | SID of the new user. |
| **AccountExpires** | Whether the account has an expiry date. |

### Suspicious Signs

| Suspicious Sign | Possible Meaning |
|---|---|
| New user created outside working hours | Unusual administrative activity. |
| Account created by unusual admin | Admin account may be compromised. |
| Account name looks like a fake service account | Possible persistence through masquerading. |
| Account quickly added to privileged group | Privilege escalation. |
| Local account created on a server | Persistence or backdoor account. |

---

## 8. Logon Types - 2, 3, 7, and 10

The logon type explains how a login happened. This field is especially important when analyzing Event ID **4624** and **4625**.

| Logon Type | Name | Meaning | SOC Example |
|---|---|---|---|
| **2** | Interactive | User logged on directly at the computer. | Keyboard login to laptop or workstation. |
| **3** | Network | User or computer accessed a resource over the network. | File share access, SMB, remote resource access. |
| **7** | Unlock | User unlocked a locked workstation. | User returns from break and unlocks screen. |
| **10** | RemoteInteractive | User logged in remotely using RDP or Terminal Services. | Admin or attacker connects through RDP. |

### How to Think Like a SOC Analyst

| Logon Type | Normal Scenario | Suspicious Scenario |
|---|---|---|
| **2** | Employee signs in locally during work hours. | Admin logs into a user workstation without reason. |
| **3** | User accesses a file share. | One account connects to many machines quickly. |
| **7** | User unlocks their own workstation. | Unlock occurs when user is away or at unusual time. |
| **10** | Approved admin RDP to a server. | RDP from unknown IP, unusual country, or after many failures. |

---

## 9. Azure Topic - Microsoft Entra ID Sign-in Logs

Microsoft Entra ID sign-in logs show cloud identity authentication activity for Azure, Microsoft 365, and other Entra-integrated applications. These logs help investigate account compromise, risky sign-ins, MFA issues, impossible travel, and suspicious access to cloud applications.

### Important Fields

| Important Field | What It Tells You |
|---|---|
| **TimeGenerated** | When the sign-in happened. |
| **UserPrincipalName** | User email or login name. |
| **AppDisplayName** | Application the user tried to access. |
| **IPAddress** | Source IP address. |
| **Location** | Country or region information. |
| **ResultType** | Success or failure code. In many queries, ResultType `0` means success and non-zero means failure. |
| **ResultDescription** | Readable reason for the sign-in result. |
| **ConditionalAccessStatus** | Conditional Access result. |
| **DeviceDetail** | Device and browser information if available. |
| **RiskLevelDuringSignIn** | Risk level if identity protection data is available. |

### Suspicious Patterns

| Suspicious Pattern | Possible Meaning |
|---|---|
| Failed logins from many countries | Password spraying or credential stuffing. |
| Successful login from unusual country | Possible account compromise. |
| Many MFA denials or repeated prompts | Possible MFA fatigue attack. |
| Login to sensitive app after unusual sign-in | Potential data access risk. |
| Legacy authentication attempts | Weak authentication path that may bypass modern controls. |
| Service principal sign-in anomaly | Possible app credential abuse. |

---

## 10. Sentinel Topic - KQL Query for Failed Logins

KQL is used in **Microsoft Sentinel** and **Log Analytics** to search, filter, summarize, and investigate security logs. Use `SecurityEvent` for Windows Security logs and `SigninLogs` for Microsoft Entra ID sign-ins.

---

### A. Windows Failed Logins - Event ID 4625

```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, Account, TargetUserName, LogonType,
          IpAddress, WorkstationName, Activity
| order by TimeGenerated desc
```

| Line | Meaning |
|---|---|
| `SecurityEvent` | Searches Windows security logs. |
| `TimeGenerated > ago(24h)` | Looks at the last 24 hours. |
| `EventID == 4625` | Keeps only failed logon events. |
| `project` | Displays the most useful investigation fields. |
| `order by` | Shows newest events first. |

---

### B. Detect Many Failed Logins from the Same IP

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4625
| summarize FailedAttempts = count(), TargetUsers = dcount(TargetUserName) by IpAddress
| where FailedAttempts > 20
| order by FailedAttempts desc
```

**Use case:** This helps detect brute-force or password spraying from one source IP.

---

### C. Failed Login Followed by Successful Login

```kql
let FailedLogons =
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project FailedTime = TimeGenerated, TargetUserName, IpAddress;

let SuccessfulLogons =
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| project SuccessTime = TimeGenerated, TargetUserName, IpAddress, LogonType, Computer;

FailedLogons
| join kind=inner SuccessfulLogons on TargetUserName, IpAddress
| where SuccessTime > FailedTime
| project TargetUserName, IpAddress, FailedTime, SuccessTime, LogonType, Computer
| order by SuccessTime desc
```

**Use case:** Repeated failures followed by a successful login can indicate that an attacker guessed the correct password.

---

### D. Microsoft Entra Failed Sign-ins

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ResultType, ResultDescription
| order by TimeGenerated desc
```

**Use case:** This query shows failed Microsoft Entra ID sign-ins, including user, IP address, location, app, and failure reason.

---

### E. Entra Password Spraying Detection

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailedAttempts = count(), UsersTargeted = dcount(UserPrincipalName) by IPAddress
| where FailedAttempts > 20 and UsersTargeted > 5
| order by FailedAttempts desc
```

**Use case:** One IP address attempting to log in to many different accounts may indicate password spraying.

---

## Simple SOC Investigation Flow

```text
Alert received
-> Identify event ID
-> Check user account
-> Check source IP, host, and location
-> Check logon type or authentication method
-> Check failed and successful login pattern
-> Check related process, service, or account creation events
-> Decide: normal, suspicious, or confirmed incident
-> Escalate, contain, or close with clear notes
```

---

## Final Memory Table

| Item | Remember This |
|---|---|
| **4624** | Successful logon. |
| **4625** | Failed logon. |
| **4688** | New process created. |
| **4697** | Service installed in Security log. |
| **7045** | New service installed in System log / Service Control Manager. |
| **4776** | NTLM credential validation. |
| **4720** | New user account created. |
| **Logon Type 2** | Local interactive login. |
| **Logon Type 3** | Network login, such as file share access. |
| **Logon Type 7** | Workstation unlock. |
| **Logon Type 10** | RDP / RemoteInteractive login. |
| **SecurityEvent** | Sentinel table for Windows Security logs. |
| **SigninLogs** | Sentinel table for Microsoft Entra sign-in logs. |

---




