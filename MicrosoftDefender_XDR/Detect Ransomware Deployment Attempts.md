**Possible Ransomware Deployment Attempts via TeamViewer by Detection of Associated Commands**

**Description:** This query detects the threat actors that attempt to launch malicious dll file using rundll.

**References:** https://www.huntress.com/blog/ransomware-deployment-attempts-via-teamviewer

```
DeviceProcessEvents
| where FileName in ('rundll32.exe')
| where ProcessCommandLine has_all ('LB3_Rundll32_pass.dll', 'gdll')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
