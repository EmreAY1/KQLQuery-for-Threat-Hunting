**Detect Possible Dumping NTDS and SYSTEM File from the Target Domain Controller**

**Description:** This query detects the threat actors that attempt to dump NTDS and SYSTEM file via associated hacktool. 

**References:** https://github.com/c-sto/gosecretsdump

```
DeviceProcessEvents
| where ProcessCommandLine has_all ('gosecretsdump', '-ntds', '-system')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
