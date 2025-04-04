# UNDER CONSTRUCTION!!!

# Threat Hunt Report: Data Exfiltration from PIP'd Employee
```
⚠️ Disclaimer: This repository and github site presents fictional threat hunting scenarios created for
educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely
coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world
cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat
hunting skills, analytical thinking, and investigative processes for professional development. It does not
reflect or promote any actual security incidents or breache
```

## 📂 Overview
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management raised concerns that John may be planning to steal proprietary information and then quit the company. I was tasked to investigate John's activities on his corporate device `sjr-workstation` using Microsoft Defender for Endpoint (MDE) to ensure nothing suspicious took place.

## 🔍 Hypothesis
Following recent behavioral concerns regarding employee John Doe—who works in a sensitive department and was
recently placed on a performance improvement plan—there is a possibility that he may attempt to exfiltrate
proprietary data before leaving the organization.

Given his administrator privileges on `sjr-workstation` and unrestricted access to
applications, it is plausible that John could:
- Download or run unauthorized scripts or tools
- Use compression utilities to collect and stage sensitive data
- Attempt to transfer files to external destinations such as cloud services, personal email, or via network
protocols outside of normal usage.

## 📥 Data Collection
To investigate potential data exfiltration activity, I collected telemetry from Microsoft Defender for Endpoint (MDE), focusing on:
- `DeviceProcessEvents` to identify execution of compression tools (e.g., 7z.exe) and PowerShell-based scripting activity (e.g., -ExecutionPolicy Bypass).
- `DeviceFileEvents` to track creation or modification of compressed files in staging locations such as C:\ProgramData\.
- `DeviceNetworkEvents` to detect outbound connections to external destinations, particularly cloud storage endpoints.

## 🧠 Data Analysis
Analysis of the collected telemetry revealed a clear timeline of suspicious activity on `sjr-workstation`. At
6:45 PM, PowerShell was executed with `-ExecutionPolicy Bypass`, likely used to run an unsigned script. This was
followed by the use of `7z.exe` to compress files containing employee data, which were staged in `C:\ProgramData\`.
Just five seconds after the ZIP file was created, PowerShell established an outbound connection to an Azure
Blob Storage endpoint, suggesting the compressed data was exfiltrated. The sequence, correlation of timestamps,
use of staging directories, and script-based orchestration all point to deliberate file preparation and exfiltration activity.

## 🕵️ Investigation

### 1. KQL Query: Confirming John Doe(`johndoe678`) successfully logged on to `sjr-workstation`.
```kql
DeviceLogonEvents
| where DeviceName == "sjr-workstation"
| where AccountName contains "johndoe678" 
| project Timestamp, DeviceId, DeviceName, ActionType, AccountName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/ad275dd1-c88f-4010-b475-0c0613a400f4)
<br>✅ A successful user logon was recorded just minutes before suspicious activity began. This provides
attribution context and confirms interactive user activity on the device. 



### 2. KQL Query: Detecting use of compression tools.
```kql
DeviceProcessEvents
| where Timestamp >= datetime(2025-04-01T18:54:00Z)
| where DeviceName == "sjr-workstation"
| where ProcessCommandLine has_any ("tar", "7z", "7zip", "WinRAR", "rar", "Compress-Archive", "Expand-Archive")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/5225cfb1-8dc0-4492-b5d0-66a230c2f8cb)
<br>✅ This log confirms that the compression utility `7z.exe` was launched by a PowerShell script (`exfiltratedata.ps1`) using an execution policy bypass. 


### 3. KQL Query: File access, creation, modification, or delation events.
```kql
DeviceFileEvents
| where Timestamp >= datetime(2025-04-01T18:54:00Z)
| where DeviceName == "sjr-workstation"
| where ActionType in~ ("FileCreated", "FileModified", "FileDeleted")
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/0188fc03-82b4-4034-8b6e-058d42bd8af0)
<br>✅ The script archived a CSV file containing what appeared to be employee data into a ZIP file named
`employee data-20250401225920.zip`. The ZIP file was successfully created in the `C:\ProgramData\` directory—a
common staging location used by threat actors to temporarily hold files before exfiltration.


### 4. KQL Query: Outbound network connections to external destinations.
```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2025-04-01T18:54:00Z)
| where DeviceName == "sjr-workstation"
| where RemoteUrl != "" and isnotempty(RemoteUrl)
| where RemotePort in (21, 22, 80, 443, 8080) // common exfil ports
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc
```
![image](https://github.com/user-attachments/assets/eda0dd11-fafe-4867-8477-e6abedc3541c)
<br>✅ This outbound connection to an Azure Blob Storage instance occurred just one second after the ZIP file
was created. The process responsible was again `powershell.exe`, executing the same script
(`exfiltratedata.ps1`). I also noticed that the zip file was exfiltrated externally over HTTPS.

## 🛡️ Recommended Response Actions for SOC/IR Team
### 1. Containment
   - Isolate `sjr-workstation` from the network immediately.
   - Terminate any active PowerShell sessions on the host.
   - Block outbound access to `*.blob.core.windows.net` and `20.60.133.132`.

### 2. Eradication & Recovery
   - Locate and remove `exfiltratedata.ps1`.
   - Locate and remove any files matching `employee-data-*.zip` or `employee-data-*.csv` in `C:\ProgramData\`.
   - Uninstall `7z.exe` if it is not officially sanctioned
   - Reset credentials for the user `johndoe678`

### 3. Forensic Follow-Up
   - Capture a full disk image and volatile memory from the workstation.
   - Review PowerShell logs and Scheduled Tasks for signs of persistence.
   - Correlate logs across systems to investigate lateral movement.

### 4. Mitigation & Monitoring
   - Deploy EDR rules to flag PowerShell executions with `-ExecutionPolicy Bypass`.
   - Enable alerting for access to `ProgramData` and use of compression utilities.
   - Monitor outbound HTTPS activity to non-sanctioned destinations.


## 🔄 Improvements
### Security Posture Improvements (Prevention)
The activity observed in this hunt — PowerShell scripting, file compression, and data exfiltration — could have been mitigated or detected earlier through the following improvements:

- Restrict PowerShell execution policies across endpoints using Group Policy or endpoint hardening tools.

- Implement application allowlisting to prevent unauthorized tools like `7z.exe` from running if not deployed by IT.

- Deploy DLP (Data Loss Prevention) policies to alert or block attempts to move sensitive files (e.g., employee data) to untrusted paths or external destinations.

- Enable full command-line auditing for PowerShell and CMD to provide better visibility in EDR/SIEM.

- Use Defender Attack Surface Reduction (ASR) rules to block or log suspicious scripting behaviors, especially in known staging directories like `C:\ProgramData\`.

### Hunting Process Refinement

This hunt was successful, but there are opportunities to sharpen our strategy for future hunts:

- Automate timeline correlation between process, file, and network events using KQL joins and visualization tools. This would speed up the investigation.

- Standardize tags and bookmarks in Defender for faster triage of scripts, outbound connections, and binaries like `7z.exe`.

- Proactively search for staging paths (e.g., `ProgramData`, `AppData\Local\Temp`) — attackers commonly use these directories.

- Broaden search patterns to include lesser-known scripting platforms (like VBScript, WScript, etc.) for potential alternate exfiltration paths.

## 🧾 Summary
### Findings
The hunt provided strong support for the hypothesis. The following activities were identified:

- PowerShell script execution using `-ExecutionPolicy Bypass`, which allows unsigned or malicious scripts to run — a known method to evade standard execution restrictions.

- Use of `7z.exe`, a legitimate compression tool, to create a ZIP archive containing sensitive employee data. This file was created in `C:\ProgramData\`, a directory commonly used by threat actors to stage files without drawing attention.

- An outbound HTTPS connection was made to an Azure Blob Storage endpoint within seconds of the archive being created, strongly indicating the file was exfiltrated.

- The entire sequence was tied to the user account `johndoe678` (John Doe), and occurred shortly after he successfully logged into the device.

### Conclusion
The threat hunt confirms that John Doe leveraged his elevated privileges to:

- Run unauthorized PowerShell scripts
- Use external compression utilities
- Stage and likely exfiltrate sensitive data to a personal cloud storage service

These actions directly align with the risk outlined in the hypothesis and represent malicious insider behavior or at minimum, a serious violation of acceptable use and data handling policies.


