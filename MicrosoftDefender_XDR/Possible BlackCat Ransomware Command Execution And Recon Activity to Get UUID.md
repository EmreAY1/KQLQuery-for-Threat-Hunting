**Detect Possible BlackCat Ransomware Command Execution And Recon Activity to Get UUID**

**Description:** BlackCat ransomware has been found to exploit compromised user credentials, unpatched or outdated firewall/VPN devices, public-facing applications, and unpatched Exchange servers to gain initial access to the system. Major initial access has been done through spearphishing and affiliates have been found buying access to the victim’s network.

BlackCat uses “wmic.exe' to retrieve system UUID from the SMBIOS, which was used later for the recovery URL in the ransom note and also to track the compromised host and prevent re-encryption of the system.

**-->** This query detects BlackCat Ransomware execution and recon activities to get UUID from the victim system.

```
DeviceProcessEvents
| where FileName in ('wmic.exe')
| where ProcessCommandLine has_all ('csproduct', 'get', 'UUID')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```

