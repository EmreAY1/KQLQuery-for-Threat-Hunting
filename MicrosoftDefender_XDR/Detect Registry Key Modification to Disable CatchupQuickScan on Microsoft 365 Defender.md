**Detect Registry Key Modification to Disable CatchupQuickScan on Microsoft 365 Defender**

**Description:** This policy setting allows you to configure catch-up scans for scheduled quick scans. A catch-up scan is a scan that is initiated because a regularly scheduled scan was missed. Usually these scheduled scans are missed because the computer was turned off at the scheduled time.

The following kql query detects possible Registry Key Modification to Disable CatchupQuickScan.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d) 
| where RegistryKey == "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Scan"
| where RegistryValueName == "DisableCatchupQuickScan"
| where RegistryValueType == "Dword" 
| where RegistryValueData == 1 
| where IsInitiatingProcessRemoteSession == true
```
