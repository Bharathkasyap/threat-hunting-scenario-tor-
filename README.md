# Detection and Analysis of Unauthorized TOR Browser Usage

<img src="img/tor-detection-banner.png" width="400" alt="TOR Detection Banner" />


## Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Bharathkasyap/threat-hunting-scenario-tor-Bharath/blob/main/Update%20threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### Step 1: File Discovery - TOR Installer

Searched **DeviceFileEvents** table for any file that had the string **‘tor’** in it and discovered what looks like the user **“employee”** downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called **‘Shopping_list’** on the desktop at May 16, 2025 4:44:36 PM. These events began at: 2025-05-16T21:38:15.9741931Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == 'threathunt-tor'
| where FileName contains 'tor'
| where InitiatingProcessAccountName != 'system'
| where Timestamp >= datetime(2025-05-16T21:38:15.9741931Z)
| order by Timestamp
| project Timestamp, FileName,DeviceName, ActionType, FolderPath, SHA256, Account= InitiatingProcessAccountName
```
<img width="1212" alt="image" src="img/Step_1.png">

---

### Step 2: Silent Installation Detection

Searched for any **process command line** that contains the string **‘ tor-browser-windows-x86_64-portable-14.5.1’** based on logs returned at **May 16, 2025, at 4:39 PM**, a process was created on the device named threathunt-tor by the user account employee. The executed command was tor-browser-windows-x86_64-portable-14.5.1.exe /S, which was run from the downloads folder located at C:\Users\employee\Downloads. The file involved is a portable version of the TOR browser, and its SHA256 hash is:f563f1d863b08dd0bfe0435049865a9f74ec2d090995d2a73b70161bb2f34f10. 

This action indicates that the user installed or ran the TOR browser on the system using a command that triggered a silent installation.

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == 'threathunt-tor'
| where ProcessCommandLine contains 'tor-browser-windows-x86_64-portable-14.5.1.exe'
| project Timestamp, DeviceName, ProcessCommandLine, ActionType, FileName, SHA256, FolderPath, AccountName 
```
<img width="1212" alt="image" src="img/Step_2.png">

---

### Step 3: Application Execution - TOR Browser 

Searched the DeviceProcessEvents table for any indications that the user “employee” actually opened the Tor browser. There is evidence that they did open this at May 16, 2025 4:40:21 PM, there were several other instances of firefox.exe (Tor) as well as Tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'threathunt-tor'
| where FileName has_any ("tor.exe", "start-tor-browser.exe", "torbrowser.exe", "firefox.exe", "tor-browser-windows", "tor-browser-windows-x86_64-portable")
or ProcessCommandLine has_any ("start-tor-browser", "torproject.org", ".onion", "Tor Browser")
| project Timestamp, DeviceName, ProcessCommandLine, ActionType, FileName, SHA256, FolderPath, AccountName 
| order by Timestamp
```
<img width="1212" alt="image" src="img/Step_3.png">

---

### Step 4: Network Communication over TOR Ports

Searched for DeviceNetworkEvents table for any identification that Tor Browser was used to establish a connection using any of the known ports. On May 16, 2025, multiple network events were recorded on the device "threathunt-tor" involving the user account "employee", indicating active use of the TOR browser. The logs show several successful outbound connections from the process tor.exe to known external IP addresses over port 9001, which is commonly used by TOR relay nodes. Additionally, there were connection attempts from firefox.exe to local proxy ports such as 9150, which was consistent with TOR browser startup behavior. Some connections were also associated with suspicious domain names resembling .onion-like encrypted traffic patterns. These activities strongly suggest the use of TOR for anonymized or proxy-based communication within the network environment. There were a couple of other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == 'threathunt-tor'
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9150, 443,80)  // Common TOR ports
| where InitiatingProcessAccountName != 'system'
| project Timestamp, DeviceName, ActionType, RemoteIP,  RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp
```
<img width="1212" alt="image" src="img/Step_4.png">

---
### Step 5: Artifact File Creation 
Searched the DeviceFileEvents table for any other files created that could potentially be a threat, focusing on filenames containing 'shopping_list'. The query revealed the creation, modification, and deletion of files related to a shopping list on the user's desktop and in their recent items/documents folder.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName contains 'shopping_list'
| project Timestamp, ActionType, FileName, FolderPath
```

<img width="1212" alt="image" src="img/Step_5.png">

---
## Chronological Event Timeline 

The following is a detailed chronological timeline of the events identified during the threat hunt:
| **Timestamp**       | **Event**                          | **Details**                                                                                        |
| ------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| 2025-05-16 16:39:20 | Silent Installation Initiated      | `tor-browser-windows-x86_64-portable-14.5.1.exe /S` executed from Downloads folder.                |
| 2025-05-16 16:40:21 | Tor.exe / Firefox.exe Launched     | Process creation logs confirm TOR browser execution (`tor.exe`, multiple `firefox.exe` instances). |
| 2025-05-16 16:41:24 | TOR Network Connection Established | Outbound IP: `88.99.7.87` via port `9001`. Additional TOR traffic observed on port `9150`.         |
| 2025-05-16 16:44:36 | Shopping List File Created         | `tor_shopping_list.txt` created on Desktop. `shopping_list.txt` also created in Documents.         |
| 2025-05-16 20:52:25 | Shopping List Modified & Deleted   | `tor_shopping_list.txt` edited and later deleted.                                                  |


The tool automatically times out after being inactive for a while. The tool requires MFA, and the employee was observed entering their credentials. The tool is not allowed to be used for personal reasons.

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
