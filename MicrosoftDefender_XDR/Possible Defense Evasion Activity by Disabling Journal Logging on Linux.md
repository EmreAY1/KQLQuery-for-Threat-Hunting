**Detect Possible Defense Evasion Activity by Disabling Journal Logging on Linux**

**Description:** Journal Logging refers to the continuous recording of system-level or file-level changes to support audit, recovery, or replication mechanisms.
Disabling journald would stop persistent logging of critical system events. Reduces visibility into startup issues, security events, and system health.

This query detects suspicious command execution on compromised linux system to disable journal logging which allows to disable the data storage function of systemd-journald on the disk.

References: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562/T1562.md#atomic-test-2---disable-journal-logging-via-systemctl-utility

```
DeviceProcessEvents
| where ProcessCommandLine has_all ('systemd-journald', 'stop')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
