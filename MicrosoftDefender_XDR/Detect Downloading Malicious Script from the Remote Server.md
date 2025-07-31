**Possible Downloading Malicious Script from the Remote Server via Associated Commands**

**Description:** This qeury detects suspicious service creation activity that performed by  Prometei Botnet which responsible for dropping additional components and connecting to C&C sersers to download additional malicious files.

**References:** https://www.trendmicro.com/en_us/research/24/j/unmasking-prometei-a-deep-dive-into-our-mxdr-findings.html

```
DeviceProcessEvents 
| where FileName  in ("sqhost.exe")
| where ProcessCommandLine has_any ('chkxwge','dcomsvc') 
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
