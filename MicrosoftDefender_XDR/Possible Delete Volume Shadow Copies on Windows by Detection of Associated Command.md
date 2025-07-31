**Possible Delete Volume Shadow Copies on Windows by Detection of Associated Command**

**Description:** This query detects deletes Windows Volume Shadow Copies. This technique is used by numerous ransomware families and APT malware such as Olympic Destroyer. Upon execution, if no shadow volumes exist the message "No items found that satisfy the query." will be displayed. If shadow volumes are present, it will delete them without printing output to the screen. This is because the /quiet parameter was passed which also suppresses the y/n confirmation prompt. Shadow copies can only be created on Windows server or Windows 8.

```
DeviceProcessEvents
| where FileName in ('vssadmin.exe')
| where ProcessCommandLine has_all ('delete', 'shadows')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
