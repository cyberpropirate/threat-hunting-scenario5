# threat-hunting-scenario5
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="3840" height="2095" alt="image" src="https://github.com/user-attachments/assets/fe5b5a65-c893-4de9-a0ce-77673ddf9142" />

# Threat Hunt Report: Unauthorized Privilege Escalation via Rogue Scheduled Task
- [Scenario Creation](https://github.com/cyberpropirate/threat-hunting-scenario5/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- schtasks.exe

##  Scenario

Management issued a directive after a threat intelligence briefing revealed increased attacker use of "living off the land" techniques, specifically involving the abuse of native Windows utilities such as schtasks.exe to gain persistence or escalate privileges. Security analysts were tasked with proactively hunting for signs of rogue scheduled task creation, especially those configured to run as SYSTEM—a common hallmark of privilege escalation attacks.
The goal of this threat hunt was to identify any unauthorized or suspicious scheduled task creations using legitimate tools like PowerShell and schtasks.exe, often seen in attacker lateral movement or persistence playbooks. Any evidence of privilege escalation would warrant immediate device isolation and escalation to security management.


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceProcessEvents`** for any PowerShell executions used to run the malicious script.
- **Check `DeviceProcessEvents`** for scheduled task creation activity by looking for schtasks.exe commands involving SYSTEM privileges.
- **Check `DeviceFileEvents`** for creation of malicious powershell script and a fake log file  used to simulate legitimate task output 

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

At `2025-08-12T22:56:46.5568941Z`, a PowerShell script named `escalate-task.ps1` was created in the Downloads directory. This script was designed to escalate privileges by creating a scheduled task that runs `cmd.exe` as SYSTEM.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName == "escalate-task.ps1"
| where DeviceName == "phishingmb"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```
<img width="2382" height="1195" alt="{DBCA9CB5-A437-4FED-BF83-15A2CB5C5F2A}" src="https://github.com/user-attachments/assets/a6f8ee94-a9ab-45d3-bbf9-acd3814787d4" />


---

### 2. Searched the `DeviceProcessEvents` Table

At `2025-08-12T22:57:18.5192587Z` the user executed the `escalate-task.ps1` script using PowerShell with an execution policy bypass flag. This execution was captured in the telemetry as a custom PowerShell command.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has "escalate-task.ps1"
| where DeviceName == "phishingmb"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```
<img width="2352" height="1109" alt="{489B2AC3-897D-426F-9BEF-AAD3EC078B8B}" src="https://github.com/user-attachments/assets/adeef65b-15e5-4b65-bfb1-e11a71a041a4" />


---

### 3. Searched the `DeviceProcessEvents` Table for Scheduled Task Creation

Immediately after the script execution, at `2025-08-12T22:57:19.7959134Z`, a new process was launched: schtasks.exe, with arguments to create a scheduled task called WinUpdateCheck that runs cmd.exe as SYSTEM. This is a strong indicator of privilege escalation.


**Query used to locate events:**

```kql
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "WinUpdateCheck"
| where DeviceName == "phishingmb"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine

```
<img width="2326" height="1168" alt="{DD2E5A96-4197-453C-BC3B-FCB57B976CB8}" src="https://github.com/user-attachments/assets/a926dead-8040-4e3c-b1f8-4ae50e39f2e5" />


---

### 4. Searched the `DeviceFileEvents` Table for Fake Log File

At `2025-08-12T22:57:19.9881427Z`, the file task-run-log.txt was created in the Downloads directory. This was a simulated log file written by the malicious PowerShell script to imitate legitimate system activity.


**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName == "task-run-log.txt"
| where ActionType == "FileCreated"
| where DeviceName == "phishingmb"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```
<img width="2376" height="1148" alt="{BF8DBBBC-1D1A-4332-8FA9-2D44B8799E85}" src="https://github.com/user-attachments/assets/20e18d26-17cd-4dbf-87b5-0626ea819e8c" />


---

## Chronological Event Timeline 

### 1. File Creation - Privilege Escalation Script

- **Timestamp:** `2025-08-12T22:56:46.5568941Z`
- **Event:** The user ecorp created a PowerShell script named `escalate-task.ps1` in the Downloads folder. This script was designed to create a rogue scheduled task that executes `cmd.exe` with SYSTEM privileges..
- **Action:** File creation detected.
- **File Path:** `C:\Users\ecorp\Downloads\escalate-task.ps1`

### 2. Process Execution - Script Launched with Execution Policy Bypass

- **Timestamp:** `2025-08-12T22:57:18.5192587Z`
- **Event:** The user executed the `escalate-task.ps1` script using PowerShell with an execution policy bypass (-ExecutionPolicy Bypass). This is a common method to evade execution restrictions.
- **Command:** `powershell.exe -ExecutionPolicy Bypass -File "C:\Users\ecorp\Downloads\escalate-task.ps1"`
- **File Path:** `C:\Users\ecorp\Downloads\escalate-task.ps1`

### 3. Process Execution - Scheduled Task Created

- **Timestamp:** `2025-08-12T22:57:19.7959134Z`
- **Event:** Immediately after executing the script, a new scheduled task named WinUpdateCheck was created using `schtasks.exe`. This task was configured to run `cmd.exe` under the SYSTEM context — a known technique for privilege escalation.
- **Action:** Process creation using `schtasks.exe` detected.
- **File Path:** `C:\Windows\System32\schtasks.exe`

### 4. Fake Log File

- **Timestamp:** `2025-08-12T22:57:19.9881427Z`
- **Event:** A file named `task-run-log.txt` was created in the Downloads directory. This file simulates a log output of the scheduled task operation to mimic legitimate administrative activity and mask malicious intent.
- **Action:** File Creation Detected.
- **File Path:** `C:\Users\ecorp\Downloads\task-run-log.txt`



---

## Summary

The user ecorp on the device phishingmb initiated a suspicious activity involving privilege escalation using PowerShell and scheduled tasks. A script named escalate-task.ps1 was created in the Downloads folder at 2025-08-12T22:56:46Z, designed to create a rogue scheduled task that executes cmd.exe as SYSTEM.
The script was executed using PowerShell with execution policy bypass, which is often used to circumvent script restrictions. Immediately afterward, a scheduled task named WinUpdateCheck was created via schtasks.exe, configured to run with SYSTEM-level privileges. This indicates a deliberate attempt to elevate local privileges on the system.
To conceal the activity, the script also generated a fake session log (task-run-log.txt) to simulate legitimate task scheduling behavior.
This chain of events reflects a clear privilege escalation attempt and demonstrates how adversaries may use built-in Windows utilities like PowerShell and Task Scheduler to gain elevated access without dropping external tools.


---

## Response Taken

Privilege escalation activity was confirmed on the endpoint phishingmb, executed by user ecorp. The malicious scheduled task was removed, and the device was isolated from the network to prevent further unauthorized access. The incident was escalated to the internal security team, and a forensic review of the user’s activity is currently underway. Additionally, endpoint detection rules were updated to alert on similar task creation patterns in the future.

---
