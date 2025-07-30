**Detect Possible Net.exe Commands to Disable Logoff-Unrestricted Password Age**

**Description:** This query detects suspicious Net.exe commands to disable logoff and the password age was set to unlimited. This behavior was used in blackcat ransomware activity.

```
DeviceProcessEvents
| where FileName in ('net.exe') or FileName in ('net1.exe')
| where ProcessCommandLine has_all ('forcelogoff:no', 'maxpwage:unlimited')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
