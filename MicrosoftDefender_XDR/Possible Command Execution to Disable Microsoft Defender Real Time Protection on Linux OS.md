**Detect Possible Command Execution to Disable Microsoft Defender Real Time Protection on Linux OS**

**Description:** "Real-Time Protection " refers to the capability of security software to continuously monitor the system for malicious activity or threats as they occur — rather than relying solely on manual scans or scheduled checks. 

**-->** This query detects the suspicious command execution to disable advanced threat protection feature of microsoft defender agent by using associted parameters on victim system that has linux OS.

```
DeviceProcessEvents
| where ProcessCommandLine has_all ('mdatp','real-time-protection', '--value', 'disabled' )
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
