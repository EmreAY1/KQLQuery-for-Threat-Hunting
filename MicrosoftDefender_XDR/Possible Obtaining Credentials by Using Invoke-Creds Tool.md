**Detect Possible Obtaining Credentials**

**Description:** This query detects the attempt to gather important credentials such as "wifi,explorer,authentication prompt,putty password,the SAM, SYSTEM and security files" from the target system via PowerShell script.

```
DeviceProcessEvents 
| where FileName  in ("powershell.exe")
| where ProcessCommandLine startswith ('Invoke-Creds')
| where ProcessCommandLine has_any ('WiFiCreds','IeCreds', 'AuthPrompt', 'PuttyKeys', 'CopySAM', 'CopyNtds')
| project Timestamp, AccountName, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
