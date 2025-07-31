**Command Execution Activity to Manipulate (disable fw, CurrentProfile) System Firewalls**

**Description:** This query detects the threat actors related with new persian RAT campaign that attempt to disable firewall and current FW profile on victim system.

```
DeviceProcessEvents
| where (ProcessCommandLine has_all ("netsh", "firewall", "set", "disable") or ProcessCommandLine has_all ("netsh", "advfirewall", "set", "currentprofile", "off"))
| project Timestamp, DeviceName, DeviceId, ReportId,  ProcessCommandLine, InitiatingProcessCommandLine
```
