**Detect Possible Deploying Malicious Applications to the Target Group**

**Description:** This query detects the threat actors that attempt to use suspicious tool in order to deploy malicious applications by abusing SCCM servers.

**References:** https://github.com/nettitude/MalSCCM , https://labs.nettitude.com/blog/introducing-malsccm/

```
DeviceProcessEvents
| where FileName in ('MalSCCM.exe')
| where ProcessCommandLine has_all ('app', 'deploy', 'groupname')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
