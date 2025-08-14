**Detect Registry Key Modification to Disable Microsoft 365 Defender Network Protection**


**Description:** Network Protection in Microsoft Defender helps prevent users from accessing malicious domains and harmful IP addresses.
It works by blocking outbound connections to dangerous or suspicious network locations, even if the URLs are accessed through applications outside the browser.
This feature can be configured via Intune, Group Policy, or PowerShell using the EnableNetworkProtection setting.
It strengthens an organization’s security posture by reducing the risk of phishing, malware downloads, and command-and-control communication.

The following KQL Query detects threat actors that attempt to disable network protection.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager"
| where RegistryValueName == "EnableNetworkProtection"
| where RegistryValueType == "Dword"
| where RegistryValueData == "0"
| where IsInitiatingProcessRemoteSession == true
```
