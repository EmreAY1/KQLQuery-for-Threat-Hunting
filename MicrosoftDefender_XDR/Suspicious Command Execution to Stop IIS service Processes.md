**Detect Suspicious Command Execution to Stop IIS service Processes**

**Descripton:** Mitre ATT&CK : Impact --> To prevent users from accessing the IIS service, BlackCat used the “iisreset” utility with “/stop” argument to stop all the IIS running services.

This query detects possible Internet Information Service processes termaination attempt to prevent legal users from accessing the IIS service. 

**Reference:** https://www.logpoint.com/en/blog/hunting-and-remediating-blackcat-ransomware/#

```
DeviceProcessEvents
| where FileName in ('iisreset.exe')
| where ProcessCommandLine has_all ('stop')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```


