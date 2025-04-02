# Threat Hunt Report: Data Exfiltration from PIP'd Employee
```
⚠️ Disclaimer: This repository and github site presents fictional threat hunting scenarios created for
educational and portfolio purposes. Any similarities to real individuals, organizations, or events are purely
coincidental. The investigation techniques, queries, and methodologies demonstrated are based on real-world
cybersecurity practices but are applied in a simulated environment. This content is intended to showcase threat
hunting skills, analytical thinking, and investigative processes for professional development. It does not
reflect or promote any actual security incidents or breache
```

## Overview
An employee named John Doe, working in a sensitive department, recently got put on a performance improvement plan (PIP). After John threw a fit, management has raised concerns that John may be planning to steal proprietary information and then quit the company. I was tasked to investigate John's activities on his corporate device `sjr-workstation` using Microsoft Defender for Endpoint (MDE) to ensure nothing suspicious took place.

## Hypothesis
Following recent behavioral concerns regarding employee John Doe—who works in a sensitive department and was
recently placed on a performance improvement plan—there is a possibility that he may attempt to exfiltrate
proprietary data before leaving the organization.

Given his administrator privileges on `sjr-workstation` and unrestricted access to
applications, it is plausible that John could:
- Download or run unauthorized scripts or tools,
- Use compression utilities to collect and stage sensitive data,
- Attempt to transfer files to external destinations such as cloud services, personal email, or via network
protocols outside of normal usage.

## Data Collection
To investigate potential insider threats involving John Doe, this hunt will focus on identifying suspicious
activity related to file access, compression, and potential data exfiltration. Microsoft Defender for Endpoint
(MDE) will be leveraged to gather telemetry from relevant logs, network traffic, and endpoint activity.

Data will be collected to inspect:
- Process execution patterns, particularly involving scripting engines and compression utilities
- File access behavior, including abnormal or bulk access to sensitive directories
- Network connections, especially to cloud services or unrecognized external destinations

Key MDE tables utilized during the hunt include:
- `DeviceFileEvents` – to monitor access to and creation of files
- `DeviceProcessEvents` – to analyze execution of processes and scripts
- `DeviceNetworkEvents` – to identify unusual outbound connections that may indicate exfiltration

## Data Analysis
The goal of this stage was to validate the hypothesis by identifying patterns, anomalies, or potential indicators of data exfiltration from John Doe’s workstation (`sjr-workstation`).

Using MDE’s advanced hunting capabilities, we queried key tables including DeviceProcessEvents,
DeviceFileEvents, and DeviceNetworkEvents to look for:

- Use of compression tools (e.g., tar, 7z, WinRAR, or PowerShell-based archiving commands).
- File access, modification, creation, or deletion events.
- Outbound network traffic to external or unauthorized destinations.

We specifically focused on identifying evidence of file archiving or scripting activity that may indicate
preparation for exfiltration. When any event resembling file compression or scripting was detected, we examined
associated telemetry.

**KQL Query**: Confirming John Doe(`johndoe678`) successfully logged on to `sjr-workstation`.
```kql
DeviceLogonEvents
| where DeviceName == "sjr-workstation"
| where AccountName contains "johndoe678" 
| project Timestamp, DeviceId, DeviceName, ActionType, AccountName
| order by Timestamp desc
```
**KQL Query**: Searching for suspicious PowerShell activity. 
```kql
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
| where Timestamp >= datetime(2025-04-01T18:45:00Z)
| where DeviceName == "sjr-workstation"
| where ProcessCommandLine has_any ("powershell", "Invoke-WebRequest", "ExecutionPolicy", "Bypass", "ProgramData")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, DeviceName
| order by Timestamp asc
```
**Observed Indicators of Compromise**
<br>At 6:45:29 PM UTC, `powershell.exe` was executed with the `-ExecutionPolicy Bypass` flag and launched via `cmd.exe`. The command originated
from a file on John Doe’s desktop and referenced a PowerShell script located in the `C:\ProgramData` directory — a non-standard and
commonly abused location for staging files or payloads.

Shortly after, at 6:45:39 PM UTC, a second PowerShell process was executed by `SenseIR.exe`, this time using the
`-ExecutionPolicy AllSigned` flag. While this may indicate legitimate activity, its timing in close proximity to the first
event raised suspicion and warranted additional review.

Between 6:47 PM and 6:56 PM UTC, multiple executions of `SearchProtocolHost.exe` were observed, triggered by `searchindexer.exe`. Although
this activity may reflect normal Windows indexing behavior, the timing suggests it could have been prompted by recent file
modifications — potentially initiated by the PowerShell script.


## Investigation
**KQL Query**: Investigating File Activity
```kql
DeviceFileEvents
| where DeviceName == "sjr-workstation"
| where Timestamp >= datetime(2025-04-01T18:45:00Z)
| project Timestamp, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```
**Analysis of Logs**
Timestamps: All activity occurred starting just seconds after the initial PowerShell execution (around 6:45:33 PM UTC), which matches the expected timeline for post-script behavior.

Action Types:
- `FileCreated` — shows that new files were generated, likely as part of script execution
- `FileRenamed` — suggests manipulation of existing files, possibly to obfuscate activity or prepare data for further actions

Many files were created or renamed in:
- `AppData\Local\Temp` — a common staging location for scripts and temporary archive files
- `AppData\Local\Microsoft\Edge` — indicating potential use of Edge or browser-based activity related to the script

Process Involved:
- All suspicious file actions were initiated by `powershell.exe` using the same bypassed execution policy as flagged earlier

The logs confirmed that John Doe’s PowerShell script created and manipulated files shortly after execution, and used known staging directories such as Temp. While this doesn’t confirm compression specifically, it validates the hypothesis of data staging and
supports continued investigation into archive creation or network exfiltration.

<br>**KQL Query:** Investigate Network Activity
```kql
DeviceNetworkEvents
| where DeviceName == "sjr-workstation"
| where Timestamp >= datetime(2025-04-01T18:45:00Z)
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol, ReportId
| order by Timestamp asc
```
**Analysis of Logs**
On April 1, 2025, at 8:13:36 PM UTC, the workstation `sjr-workstation` initiated a network request using powershell.exe. This command was executed with the `-ExecutionPolicy Bypass` flag, allowing it to circumvent PowerShell’s default script execution restrictions. It downloaded a remote script named `pwncrypt.ps1` from GitHub and saved it to the `C:\ProgramData` directory — a known staging location often used by threat actors to avoid scrutiny.

The request was made to IP address `185.199.111.133`, resolving to GitHub's raw content delivery infrastructure. This behavior strongly indicated an attempt to retrieve and stage a script potentially related to malicious activity. The filename `pwncrypt.ps1` suggested the script may have been designed for encryption or other offensive functions, possibly aligning with tactics associated with ransomware or credential theft.

This activity was highly suspicious due to:
- Use of execution policy bypass
- External script download from a public repository
- Storage in an obfuscated directory
- The suggestive naming convention of the script


<br>3. Validate the Origin of SenseIR.exe
Goal: Determine if SenseIR.exe is part of a legitimate tool or potentially unwanted software.
```kql
```


<br>4. Look for Archive Tool Use
Goal: Confirm if John used tools like 7z.exe, winrar.exe, etc., possibly to compress data before exfiltration.
```kql
```





