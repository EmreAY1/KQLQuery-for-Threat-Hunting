**Detect Suspicious Activity to Steal Tokens of the Users without Touching Lsass by Abusing RPC Named Pipe Service**

**Description:** This query detects the threat actors that attempt to steal tokens of the victims without using normal token Impersonation technique. The adversaries perform this attack by using associated tool. 

**References:** https://book.hacktricks.xyz/windows-hardening/stealing-credentials/wts-impersonator , https://github.com/OmriBaso/WTSImpersonator

```
DeviceProcessEvents
| where FileName in ('WTSImpersonator.exe')
| where ProcessCommandLine has_all ('-m', 'enum')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
