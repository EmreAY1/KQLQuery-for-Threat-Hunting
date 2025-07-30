**Detect Possible Windows Volume Shadow Copies Delete by Using WMI**

**Description:** Volume Shadow Copies (also known as Shadow Copies or VSS – Volume Shadow Copy Service) is a snapshot-based backup feature in Windows operating systems that allows you to create point-in-time copies of files or entire volumes, even while they are in use.

This query detects Windows Volume Shadow Copies deletion activity via WMI. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Many ransomware variants delete shadow copies to prevent recovery.

**Reference:** https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.md#atomic-test-2---windows---delete-volume-shadow-copies-via-wmi
```
DeviceProcessEvents
| where FileName in ('wmic.exe')
| where ProcessCommandLine has_all ('delete', 'shadowcopy')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
