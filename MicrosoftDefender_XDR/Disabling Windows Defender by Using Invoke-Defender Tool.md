**Possible Disabling Windows Defender by Using Invoke-Defender Tool**

**Description:** This query detects the attempt to disable windows defender via suspicious tool.


```
DeviceProcessEvents 
| where FileName contains "powershell"
| where ProcessCommandLine startswith ('Invoke-DefenderTools')
| where ProcessCommandLine has_any ('GetExcludes','AddExclude', 'DisableRtm', 'DisableAmsi')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
