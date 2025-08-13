# Threat Event (Unauthorized Privilege Escalation)
**Rogue Scheduled Task for Gaining SYSTEM-Level Persistence**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Opened PowerShell with user privileges
2. Downloaded a rogue script file ( `escalate-task.ps1`) from the internet
3. The script created a scheduled task named “WinUpdateCheck”, designed to run as NT AUTHORITY\SYSTEM
4. The task was configured to launch `cmd.exe` silently and allow SYSTEM-level shell execution

5. A fake log file (`task-run-log.txt`) was created in the Downloads folder to make the activity look like a system maintenance action


---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect creation of .ps1 file and fake task run logs |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Detect execution of PowerShell and schtasks.exe used to create tasks|



---

## Related Queries:
```kql
// Detect rogue task creation using schtasks
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "WinUpdateCheck"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect PowerShell script execution
DeviceProcessEvents
| where FileName == "powershell.exe" and ProcessCommandLine contains "escalate-task.ps1"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect creation of script file and fake log
DeviceFileEvents
| where FileName in ("escalate-task.ps1", "task-run-log.txt")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

```

---

## Created By:
- **Author Name**: Musie Berhe
- **Author Contact**: 
- **Date**: August 12, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `August  12, 2025`  | `Musie Berhe`   
