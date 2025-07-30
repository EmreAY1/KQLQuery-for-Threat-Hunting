**Detect Possible Command Execution of Akira Ransomware Linux Variants to Disable CoreDump File**

**Description:** Emerging in early 2023, the Howling Scorpius ransomware group is the entity behind the Akira ransomware-as-a-service (RaaS), which has consistently ranked in recent months among the top five most active ransomware groups. Its double extortion strategy significantly amplifies the threat it poses.
Howling Scorpius targets small to medium-sized businesses in North America, Europe and Australia, across various sectors. Affected industries include education, consulting, government, manufacturing, telecommunications, technology and pharmaceuticals.

This query detects the suspicious ESXCLI command execution performed by akira ransomware to disable the coredump file on victim system which is linux OS. 

```
DeviceProcessEvents
| where ProcessCommandLine has_all ('coredump', 'file', 'set', '--unconfigure')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
