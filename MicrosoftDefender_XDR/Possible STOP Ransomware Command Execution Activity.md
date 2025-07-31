**Detect Possible STOP Ransomware Command Execution Activity**

**Description:** This query is designed to identify potentially harmful activities related to the STOP ransomware by examining command lines executed on devices. It specifically looks for command lines that include certain suspicious parameters:

The command line must contain either "--Admin" or "--ForNetRes".
Additionally, it must include both "IsAutoStart" and "IsTask".

When these conditions are met, the query retrieves and displays the following information for further analysis: the time the event occurred (Timestamp), the name of the device (DeviceName), the device's unique identifier (DeviceId), a report identifier (ReportId), the command line that was executed (ProcessCommandLine), and the command line of the process that initiated it (InitiatingProcessCommandLine).

```
DeviceProcessEvents
| where ProcessCommandLine has_any ("--Admin", "--ForNetRes")
| where ProcessCommandLine has_all ("IsAutoStart", "IsTask")
| project Timestamp, DeviceName, DeviceId, ReportId, ProcessCommandLine, InitiatingProcessCommandLine
```
