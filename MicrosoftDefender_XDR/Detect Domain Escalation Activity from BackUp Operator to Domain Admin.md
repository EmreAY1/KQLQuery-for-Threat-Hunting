**Detect Possible Domain Escalation Activity from BackUp Operator to Domain Admin via Malicious Tool**

**Description:** This rule detects the adversaries that attempt to use malicious tool which has four different modes to perform domain escalation from the Backup Operators group to domain admin

**References:** https://github.com/improsec/BackupOperatorToolkit

```
DeviceProcessEvents
| where FileName in ('BackupOperatorToolkit.exe')
| where ProcessCommandLine has_any ('SERVICE', 'DSRM', 'DUMP', 'IFEO')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
