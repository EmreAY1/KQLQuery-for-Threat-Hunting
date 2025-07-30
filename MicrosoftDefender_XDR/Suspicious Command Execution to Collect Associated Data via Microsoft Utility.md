**Detect Suspicious Command Execution to Collect Associated Data via Microsoft Utility**

**Description:** This query detects the command execution that aim to collect performance data such as Process Queue Length details in the processors on victim system by using microsoft utility via associated parameters.

**References:** https://thedfirreport.com/2024/12/02/the-curious-case-of-an-egg-cellent-resume/

```
DeviceProcessEvents
| where FileName in ('typeperf.exe')
| where ProcessCommandLine has_all ('\\System\\Processor', 'Queue', 'Length', '-si')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
