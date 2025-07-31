**Possible Registry Key Modification to Disable Windows NotificationCenter**

**Description:** If this setting is disabled, Notifications and Action Center is not displayed in the notification area. The user will be able to read notifications when they appear, but they won't be able to review any notifications they miss.


```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey endswith "\\Microsoft\\Windows\\Explorer"
| where RegistryValueName == "DisableNotificationCenter"
| where RegistryValueData == "1"
| where IsInitiatingProcessRemoteSession == true
```
