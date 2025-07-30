**Suspicious Command Execution to Connect with the C2 Server by Using Rundll32.exe**

**Description:** This query detects the command execution that aim to evade detection and connect with the command and control server by using system binary,Rundll32.exe, with associated parameter.

```
DeviceProcessEvents
| where FileName in ('rundll32.exe')
| where ProcessCommandLine has_all ('adb.dll', 'Control_RunDLL')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
