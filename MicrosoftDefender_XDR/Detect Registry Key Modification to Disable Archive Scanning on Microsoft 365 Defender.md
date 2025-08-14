**Detect Registry Key Modification to Disable Archive Scanning**


**Description:** ArchiveScanning in Microsoft Defender enables the scanning of archive files such as .zip, .cab, and .rar for malicious content.
When enabled, Defender will inspect the contents of compressed files during real-time or scheduled scans.
This feature can be configured via Intune or Group Policy using the DisableArchiveScanning setting.
It enhances threat detection by identifying hidden malware inside compressed or packaged files.

The following KQL Query detects adversaries that attempt to Disable Archive Scanning.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey endswith "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Scan"
| where RegistryValueName == "DisableArchiveScanning"
| where RegistryValueType == "Dword" 
| where RegistryValueData == 1 
| where IsInitiatingProcessRemoteSession == true
```
