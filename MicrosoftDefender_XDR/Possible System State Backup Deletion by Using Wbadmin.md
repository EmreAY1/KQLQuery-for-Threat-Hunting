**Detect Possible System State Backup Deletion by Using Wbadmin.exe**

**Description:** System State Backup refers to the process of backing up critical system components required to restore a computer to a working state after a system failure, corruption, or major misconfiguration — without reinstalling the operating system from scratch.

**-->** This query detects the deletion of backups or system state backups via "wbadmin.exe". This technique is used by numerous ransomware families and actors. This may only be successful on server platforms that have Windows Backup enabled.

```
DeviceProcessEvents
| where FileName in ('wbadmin.exe')
| where ProcessCommandLine has_all ('delete', 'systemstatebackup')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
