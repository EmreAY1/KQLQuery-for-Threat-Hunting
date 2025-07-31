**Detect Possible Registry Key Modification to Disable LSA Protection**

**Description:** This rule detects Registry Key Modification to Disable LSA Protection.The LSA controls and manages user rights information, password hashes and other important bits of information in memory. Attacker tools, such as mimikatz, rely on accessing this content to scrape password hashes or clear-text passwords. Enabling LSA Protection configures Windows to control the information stored in memory in a more secure fashion - specifically, to prevent non-protected processes from accessing that data.

```
DeviceRegistryEvents
| where Timestamp >= ago(7d)
| where RegistryKey endswith "\\SYSTEM\\CurrentControlSet\\Control\\LSA"
| where RegistryValueName == "RunAsPPL"
| where RegistryValueData == "0"
| where IsInitiatingProcessRemoteSession == true 
```
