**Detect Possible Windows Event Logs Enumeration Activity**

**Description:** This query detects the enumeration activity to get all available event logs such as security, application, system on compromised system. The threat actors can use this method to discover potantial weaknesses in the logging configuration and after getting these information they can modify their further attacks. 

```
DeviceProcessEvents
| where FileName in ('wevtutil.exe')
| where ProcessCommandLine has_any ('enum-logs')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
