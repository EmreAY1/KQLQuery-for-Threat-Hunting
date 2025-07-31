**Detect Possible Exela Stealer behavior to Ensure Persistence by Creating Suspicious Scheduled Task**

**Description:** This rule detects the exela stealer that attempt to create suspicious scheduled task for ensuring its persistence and automatically run malicious executable file on logon.


```
DeviceProcessEvents
| where FileName in ('schtasks.exe')
| where ProcessCommandLine has_all ('AutoUpdateCheckerOnLogon', 'ExelaUpdateService')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
