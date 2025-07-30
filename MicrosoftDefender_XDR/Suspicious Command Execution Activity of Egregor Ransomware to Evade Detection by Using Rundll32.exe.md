**Detect Suspicious Command Execution Activity of Egregor Ransomware to Evade Detection by Using Rundll32.exe**

**Description:** Egregor, a variant of the Sekhmet ransomware family, remains one of the most active and aggressive ransomware strains in the past year and widely believed to be the successor of the Maze ransomware. Egregor made its debut in mid-September 2020, at the same time Maze ransomware publicly announced its retirement. During this short time, Egregor has managed to compromise a large number of victims across the globe. Victims include high-profile companies like Kmart, Ubisoft, Crytek and Randstad. The spike in Egregor’s activity signals that Maze affiliates quickly switched to Egregor without any hitch.

This query detects command execution which performs by egregor ransomware that aim to compromise organizations, steal sensitive user data, encrypt data, and demand a ransom to exchange encrypted documents. 

```
DeviceProcessEvents
| where FileName in ('rundll32.exe')
| where ProcessCommandLine has_all ('DllRegisterServer', '-multiproc')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

