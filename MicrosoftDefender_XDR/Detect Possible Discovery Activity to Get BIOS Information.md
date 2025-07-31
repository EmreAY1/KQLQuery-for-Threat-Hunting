**Detect Possible Discovery Activity to Get BIOS Information**

**Description:** This query detects the threat actors that attempt to query to the associated registry key for getting BIOS information which allows the threat actors to detect sandboxing environments on victim system.

```
DeviceProcessEvents
| where FileName in ('reg.exe')
| where ProcessCommandLine has_all ('query', 'SystemBiosVersion', '\\HARDWARE\\DESCRIPTION\\System')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
