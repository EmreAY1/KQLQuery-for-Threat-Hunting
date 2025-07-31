**Possible Registry Key Modification to Enable RDP Connection Without Password**

**Description:** An account without a password can allow unauthorized access to a system as only the username would be required. Password policies should prevent accounts with blank passwords from existing on a system. However, if a local account with a blank password does exist, enabling this setting will prevent network access, limiting the account to local console logon only.


```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey endswith "\\ControlSet001\\Control\\Lsa"
| where RegistryValueName == "LimitBlankPasswordUse"
| where RegistryValueData == "0"
| where IsInitiatingProcessRemoteSession == true
```

