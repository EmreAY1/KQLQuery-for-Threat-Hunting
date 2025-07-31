**Possible Extracting DPAPI Backup Keys from Domain Controller via Associated Mimikatz Command**

**Description:** This query detects suspicious command execution that aim to extract dpapi backup key from the domain controller which allows the threat actors to get decrypt any user's master key and user's secrets such as chrome secrets which contains user's login data.

```
DeviceProcessEvents 
| where ProcessCommandLine has_all ('lsadump::backupkeys','system', 'export')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
