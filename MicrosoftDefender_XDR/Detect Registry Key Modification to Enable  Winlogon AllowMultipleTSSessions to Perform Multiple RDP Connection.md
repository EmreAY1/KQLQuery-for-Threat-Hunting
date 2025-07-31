**Registry Key Modification to Enable  Winlogon AllowMultipleTSSessions to Perform Multiple RDP Connection**

**Description:** This query detects when the 'AllowMultipleTSSessions' value is enabled. Which allows for multiple Remote Desktop connection sessions to be opened at once. This is often used by attacker as a way to connect to an RDP session without disconnecting the other users.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey endswith "\\Microsoft\\Windows NT\\Terminal Services"
| where RegistryValueName == "AllowMultipleTSSessions"
| where RegistryValueData == "1"
| where IsInitiatingProcessRemoteSession == true
```
