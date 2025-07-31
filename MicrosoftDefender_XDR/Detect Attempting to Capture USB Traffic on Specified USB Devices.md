**Detect Attempting to Capture USB Traffic on Specified USB Devices**

**Description:** This query detects threat actors that attempt to capture USB traffic on specified USB devices on victim environments. This activity was used by Crambus group in their activity. 

**References:** https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/crambus-middle-east-government

```
DeviceProcessEvents
| where FileName in ('usbpcapcmd.exe')
| where ProcessCommandLine has_all ('--extcap-interfaces')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

