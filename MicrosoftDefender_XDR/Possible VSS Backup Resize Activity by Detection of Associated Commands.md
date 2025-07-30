**Detect Possible VSS Backup Resize Activity by Detection of Associated Commands**

**Description:** Clop infection is that it tries to inhibit the system recovery by deleting the shadow copy, deleting the Windows backup catalog, and modifying the boot configuration to disable Windows automatic recovery features.

**-->** This query detects Clop Ransomware scenarios where an attacker attempts to delete or resize existing VSS backup.

```
DeviceProcessEvents
| where FileName in ('vssadmin.exe')
| where ProcessCommandLine has_all ('resize', 'shadowstorage', 'unbounded')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
