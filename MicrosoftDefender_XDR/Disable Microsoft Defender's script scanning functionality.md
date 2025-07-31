**Detect Disable Microsoft Defender's script scanning functionality**

**Description:** This query is designed to identify any attempts to turn off the script scanning feature of Microsoft Defender within the last 7 days. It specifically looks for changes made to a particular registry key that controls real-time protection settings. The query filters for:

1.Events from the past week.

2.Modifications to the registry key related to Microsoft Defender's real-time protection.

3.Changes where the specific setting "DisableScriptScanning" is altered.

4.The change is of type "Dword" and the value is set to 1, indicating that script scanning has been disabled.

5.The modification was initiated from a remote session, suggesting potential unauthorized access.

```
DeviceRegistryEvents 
| where Timestamp >= ago(7d) 
| where RegistryKey == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Real-Time Protection" 
| where RegistryValueName == "DisableScriptScanning" 
| where RegistryValueType == "Dword" 
| where RegistryValueData == 1 
| where IsInitiatingProcessRemoteSession == true

```
