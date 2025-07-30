**Detect Possible Command Execution to Enumerate Stored Certificates on Linux**

**Description:** Enumerate Stored Certificates on Linux" refers to the process of identifying and listing all digital certificates that are stored on a Linux system. These certificates are used to establish secure communication (TLS/SSL), authenticate users or services, and verify the integrity of data.

Enumerating stored certificates is a standard task in system hardening and incident response. Any unexpected or unauthorized certificate found during this process could indicate:

Man-in-the-middle attack preparation (e.g., malicious root CA installed).

Malware persistence mechanism using custom certs.

Misconfiguration that exposes the system to TLS validation bypass.

**-->** This query detects the suspicious command execution to get stored certificates from the linux environment via using associated commands.

```
DeviceProcessEvents
| where ProcessCommandLine has_all ('ls','-lsaR', '/etc/ssl')
| project Timestamp, AccountName, DeviceName,DeviceId,ReportId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
```
