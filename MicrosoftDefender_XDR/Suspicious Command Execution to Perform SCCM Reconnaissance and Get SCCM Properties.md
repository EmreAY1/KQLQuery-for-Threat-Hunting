**Detect Suspicious Command Execution to Perform SCCM Reconnaissance and Get SCCM Properties**

**Description:** This query detects the powershell command ADSISearcher with associated parameter that aim to enumerate whether SCCM is present in a victim environment and get properties such as SCCM site code, SCCM Management point etc.


```
DeviceProcessEvents 
| where FileName  in ("powershell.exe")
| where ProcessCommandLine has_all ('ADSISearcher','objectClass', 'mSSMSManagementPoint', 'Properties') 
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
