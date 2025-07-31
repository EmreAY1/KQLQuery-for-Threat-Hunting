**Malicious Zoom Installer Detection**

**Description:** This query is designed to identify potentially harmful activities related to the Zoom installer on a device. It specifically looks for instances where the program "rundll32.exe" is used to run a file named "maker.dll" with the "init" parameter. This behavior is associated with the IcedId Loader malware campaign. The query retrieves and displays information such as the time of the event, the device's name and ID, a report ID, the command line used for the process, and the command line of the process that initiated it.

```
DeviceProcessEvents
| where FileName in ("rundll32.exe")
| where ProcessCommandLine has_all ("maker.dll", "init")
| project Timestamp, DeviceName, DeviceId, ReportId, ProcessCommandLine, InitiatingProcessCommandLine
```
