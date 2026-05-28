# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

- [Scenario Creation](https://github.com/CodeGuardian21/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged

- EDR (Endpoint, Detection and Response) Platform: Microsoft Defender for Endpoint
- Windows 11 Virtual Machines (Microsoft Azure)
- KQL (Kusto Query Language)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC (Indicator of Compromise) Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceProcessEvents` Table for TOR binaries

Queried DeviceProcessEvents to identify executions of Tor related binaries (tor.exe, tor-browser.exe) across endpoints.

```kql
DeviceProcessEvents
| where FileName has_any ("tor.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```

The results that displayed showed AccountName "one" on DeviceName "vmwin" had the Tor related binaries.

---

### 2. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "one" actually opened the TOR browser. There was evidence that they did open it at `2026-04-21T02:23:03.9989335Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "vmwin"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```

<img width="1298" height="265" alt="image" src="https://github.com/user-attachments/assets/7b8b52dd-8829-451d-b7f1-4d7193181817" />

---

### 3. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at 2026-04-20 10:22:38 PM EST `(2026-04-2026-04-21T02:22:38.6443216Z)`, an employee on the "vmwin" device ran the file `tor-browser-windows-x86_64-portable-15.0.9.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "vmwin"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```

<img width="1313" height="24" alt="image" src="https://github.com/user-attachments/assets/a8fce088-6317-4ad5-910a-1f7f6a2e9852" />

---

### 4. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it, and discovered what looks like the user “one” downloaded a tor installer, then did something that resulted in many tor-related files being copied to the desktop, and the creation of a file called “tor-shopping-list.txt on the desktop. These events began at : 2026-04-20 10:22:38 PM EST (2026-04-21T02:22:38.6443216Z . The timestamp in Microsoft Defender is in UTC)

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "vmwin"
| where InitiatingProcessAccountName == "one"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-21T02:22:38.6443216Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```

<img width="1106" height="361" alt="image" src="https://github.com/user-attachments/assets/e094a44a-1094-470e-9118-77835fc2dbda" />

---

### 5. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. On April 20, 2026 at 10:23 PM, an employee on the "vmwin" device successfully established a connection to the remote IP address `185.216.35.222` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\one\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "vmwin"
| where InitiatingProcessAccountName == "one"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp asc

```

<img width="1300" height="165" alt="image" src="https://github.com/user-attachments/assets/4dd4a91e-520a-4f12-aa78-4c8c2a348cb0" />

---

## Chronological Event Timeline

| Time (EST)  | Action Type       | Event Details                                                                                           |
| ----------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| 10:22:38 PM | ProcessCreated    | User "one" launched tor-browser-windows-x86_64-portable-15.0.9.exe with a silent flag (/S)            |
| 10:22:50 PM | FileCreated       | Tor browser components (tor.exe, tor.txt, Torbutton.txt, Tor-Launcher.txt) were created in C:\Browser\  |
| 10:22:55 PM | FileCreated       | Tor Browser.lnk was created                                                                             |
| 10:23:03 PM | ProcessCreated    | firefox.exe (Tor) was initialized                                                                       |
| 10:23:04 PM | FileCreated       | storage.sqlite was created                                                                              |
| 10:23:05 PM | ProcessCreated    | tor.exe process was started                                                                             |
| 10:23:08 PM | FileCreated       | storage-sync-v2.sqlite was created                                                                      |
| 10:23:15 PM | FileCreated       | tor-shopping-list.txt was created on the desktop                                                        |
| 10:23:35 PM | ConnectionSuccess | Connection established via firefox.exe to 127.0.0.1:9150                                                |
| 10:23:43 PM | ConnectionSuccess | Network connection to 185.216.35.222 on port 9001 via tor.exe                                           |
| 10:37:24 PM | FileCreated       | tor-shopping-list.lnk created on the desktop                                                            |
| 10:37:24 PM | FileRenamed       | tor-shopping-list.txt renamed on the desktop                                                            |
| 10:38:21 PM | FileModified      | tor-shopping-list.txt was modified                                                                      |

---

## Summary

On April 20, 2026, between 10:22 PM and 10:38 PM, user "one" performed an unauthorized deployment of the Tor Browser on the vmwin device using a silent installer. Immediately following the installation and the initialization of the tor.exe and firefox.exe processes, the user established an external network connection to the Tor infrastructure at IP address 185.216.35.222 on port 9001. Concurrent with these activities, the user created, renamed, and modified a file named tor-shopping-list.txt on the desktop, indicating that the browser was being utilized for shopping activities.

---

## Response Taken

TOR usage was confirmed on the endpoint `vmwin` by the user `one`. The device was isolated, and the user's direct manager was notified.

---
