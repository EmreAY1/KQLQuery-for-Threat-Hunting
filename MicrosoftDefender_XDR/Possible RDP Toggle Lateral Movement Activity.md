**Detect Possible RDP Toggle Lateral Movement Activity**

**Description:** This query is designed to identify potential security threats by detecting attempts to enable Remote Desktop on a device using a specific command-line tool, "wmic.exe." This technique is commonly used in ransomware attacks after an intruder has gained access to a system.

```
DeviceProcessEvents
| where FileName in ("wmic.exe")
| where ProcessCommandLine has_all ("rdtoggle", "SetAllowTSConnections", "1")
| project Timestamp, DeviceName, DeviceId, ReportId, ProcessCommandLine, InitiatingProcessCommandLine
```
