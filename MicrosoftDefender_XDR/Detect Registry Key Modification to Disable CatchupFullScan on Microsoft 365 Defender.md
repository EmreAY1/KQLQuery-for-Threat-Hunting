**Detect Registry Key Modification to Disable CatchupFullScan on Microsoft 365 Defender**

**Description:** Catch-up Full Scan in Microsoft Defender ensures that scheduled full scans are not missed.
If a device is turned off or unavailable during the scheduled time, the scan will automatically run at the next opportunity.
This feature can be configured or enforced via Intune or Group Policy using the DisableCatchupFullScan setting.
It helps maintain consistent security posture by ensuring periodic scans are always completed.

The following KQL query detects possible threat actors that attempt to Disable CatchupFullScan.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d) 
| where RegistryKey == "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\Scan"
| where RegistryValueName == "DisableCatchupFullScan"
| where RegistryValueType == "Dword" 
| where RegistryValueData == 1 
| where IsInitiatingProcessRemoteSession == true
```
