# TryHackMe: Sysinternals Room Summary

Room URL: https://tryhackme.com/room/btsysinternalssg

---
# Introduction
What are the tools known as Sysinternals?

The Sysinternals tools is a compilation of over 70+ Windows-based tools. Each of the tools falls into one of the following categories:

- File and Disk Utilities
- Networking Utilities
- Process Utilities
- Security Utilities
- System Information
- Miscellaneous

If you wish to download a tool or two but not the entire suite, you can navigate to [the Sysinternals Utilities Index page](https://learn.microsoft.com/en-us/sysinternals/downloads/)

if you wish to run the tool from the web.--> https://live.sysinternals.com/

If you wish to download the Sysinternals Suite --> https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

---
# File and Disk Utilities

## 1. Sigcheck

**Description:**  
Sigcheck is a command-line utility that shows detailed file information, including version, timestamp, and digital signatures. It can also query VirusTotal to check if a file is malicious.

**Example Command:**
```cmd
sigcheck -vt explorer.exe
```

[Sigcheck - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)

## 2. Streams
**Description:** 

Streams is a command-line utility that shows NTFS alternate data streams (ADS) attached to files. ADS can be used to hide metadata or malicious code. This tool can list and optionally delete them.

**Example Command:**
```cmd
streams -s -d C:\Users\YourName\Documents
```
This recursively deletes all ADS in the specified directory.

[Streams - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/streams)

## 3. SDelete
**Description:**

SDelete securely deletes files or cleans free space to prevent recovery. It uses the DoD 5220.22-M standard for secure deletion, making it useful for wiping sensitive data.

**Example Command:**
```cmd
sdelete -p 3 -z C:
```
[SDelete - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete)

## Answer the questions below

### Q1. There is a txt file on the desktop named file.txt. Using one of the three discussed tools in this task, what is the text within the ADS?

- use the stream tool to return the hidden file of the `file.txt`
 ```ps
streams C:\Users\Administrator\Desktop\file.txt -accepteula  
```

![Screenshot 2025-05-12 133840](https://github.com/user-attachments/assets/d054ba84-906c-412b-a88a-3e99839dea40)

- then change the directory to the file location `cd .\Desktop\`
- then use Notepad to view the contents of the hidden file
```ps
notepad.exe file.txt:ads.txt
```
![Screenshot 2025-05-12 131308](https://github.com/user-attachments/assets/9684ce72-32d1-4ae9-8772-af9a8cfb943c)

- There is another way, to request all streams associate with `file.txt`
```ps
 get-item -Path .\file.txt -stream * 
```
 ![Screenshot 2025-05-12 134133](https://github.com/user-attachments/assets/2760b5b8-eb94-4d56-9d87-2e24f71d3c93)


Ans: ***I am hiding in the stream.***

---
# Networking Utilities

## 1. TCPView

**Description:**  
TCPView is a Windows Sysinternals utility that provides a real-time, detailed view of all TCP and UDP endpoints on your system. It displays local and remote addresses, ports, connection states, and the owning process name. It's a graphical and more intuitive alternative to the `netstat` command.

**Key Uses:**
- Monitor active network connections in real-time.
- Identify suspicious or unauthorized network activity.
- Detect malware attempting to call home.
- Troubleshoot application-level networking issues or port conflicts.

**Example Usage:**

To launch TCPView:

1. Download and extract the ZIP file from the official site.
2. Run `Tcpview.exe`.

**Command-line launch (from TCPView directory):**

```cmd
tcpview.exe
```

This opens the GUI, where you can:
- View current connections and their state (e.g., ESTABLISHED, TIME_WAIT).
- Sort by columns such as **Process**, **Remote Address**, or **State**.
- Right-click a connection to **Close Connection** or **Kill Process**.

**Official Resource:**  
[TCPView - Microsoft Docs](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview)

---
# Process Utilities


## 1. Autoruns

*Autoruns* shows which programs are configured to run during system bootup or login. It provides comprehensive details about auto-starting locations, including registry keys, startup folders, services, drivers, and more.

### Key Features
- Displays all auto-start entries across multiple categories
- Helps detect malware persistence mechanisms
- Can disable or delete startup items
- Includes "Hide Microsoft Entries" option to focus on third-party apps

### Use Cases
- Troubleshooting slow boot/login
- Identifying malware auto-starts
- Managing startup programs

[Microsoft Sysinternals - Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)


## 2. ProcDump

*ProcDump* is a command-line utility that is used to monitor applications for CPU spikes and generate crash dumps during hangs or crashes. These dumps are useful for advanced debugging and diagnostics.

### Key Features
- Captures dumps based on CPU, memory, or unhandled exceptions
- Supports triggering on performance counters or specific events
- Helps diagnose high CPU usage and application crashes

### Use Cases
- Debugging application hangs or crashes
- Analyzing memory dumps with WinDbg
- Automating dump collection during stress testing

[Microsoft Sysinternals - ProcDump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)


## 3. Process Explorer

*Process Explorer* is an advanced task manager that shows detailed information about running processes, including parent-child relationships, DLLs, handles, and performance metrics.

### Key Features
- Tree-based view of processes
- Displays DLLs and handles opened by processes
- Provides detailed performance and CPU usage info
- Can search for specific file or registry handles

### Use Cases
- Troubleshooting system performance issues
- Detecting suspicious processes
- Investigating file locks or resource usage

[Microsoft Sysinternals - Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)


## 4. Process Monitor

*Process Monitor (ProcMon)* is a real-time monitoring tool that captures and displays system activity related to file systems, registry, processes, and threads.

### Key Features
- Real-time event capture
- Filtering and searching capabilities
- Includes stack traces for detailed debugging
- Can save logs for offline analysis

### Use Cases
- Debugging application behavior
- Identifying malware behavior
- Diagnosing permission or file access issues

[Microsoft Sysinternals - Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)


## 5. PsExec

*PsExec* is a lightweight telnet-replacement tool that allows you to execute processes on remote systems. It's part of the PsTools suite.

### Key Features
- Remote execution of commands or applications
- Option to run as SYSTEM or other users
- Redirects output back to the local console
- Supports interactive sessions

### Use Cases
- Remote administration
- Running tools with elevated privileges
- Deploying scripts across machines


[Microsoft Sysinternals - PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

---
# Security Utilities

## 1. Sysmon (System Monitor)

*Sysmon* is a Windows system service and device driver that logs system activity to the Windows Event Log. It provides detailed information about process creations, network connections, file creation times, and more — helping security analysts and administrators monitor and investigate suspicious behavior.

### Key Features
- Logs process creation with full command-line and hashes
- Tracks network connections, including source and destination IPs
- Captures changes to file creation time
- Logs driver and image loads
- Detects process access events and named pipe events
- Highly customizable configuration via XML

### Use Cases
- Threat hunting and forensic investigations
- Monitoring for malware or advanced persistent threats (APTs)
- Creating detection rules with SIEM tools (e.g., Splunk, Sentinel)

### Configuration
Sysmon requires an XML configuration file to specify which events to log. You can use community templates like the one from [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) or customize your own for tailored monitoring.

[Microsoft Sysinternals - Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

---
# System Information

### 1. WinObj

*WinObj* is a GUI tool for inspecting the internal Windows Object Manager namespace. It shows kernel objects like devices, symbolic links, named pipes, and more, which are typically hidden from standard user interfaces.

#### Key Features
- Graphical interface to explore the \ObjectManager namespace
- Accesses objects like \Device, \Driver, and \BaseNamedObjects
- Helps developers and security professionals understand system-level components

#### Use Cases
- Investigating kernel-mode objects
- Debugging object creation by applications
- Studying how Windows organizes OS resources

[Microsoft Sysinternals - WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj)

---
# Miscellaneous

### 1. BgInfo

*BgInfo* displays key system information (e.g., IP address, computer name, OS version) directly on the desktop background. It's commonly used in enterprise environments for quick system identification.

#### Key Features
- Auto-updates desktop wallpaper with live system data
- Customizable layout and font styles
- Supports scripting and automation for deployment

#### Use Cases
- Displaying system info on remote desktops
- Asset tracking in large organizations
- Troubleshooting user-reported issues without logging in

[Microsoft Sysinternals - BgInfo](https://learn.microsoft.com/en-us/sysinternals/downloads/bginfo)



### 2. RegJump

*RegJump* is a command-line utility that opens the Windows Registry Editor (regedit) at a specific path. It simplifies navigation by skipping the manual browsing of nested registry keys.

#### Key Features
- Quickly jumps to specified registry paths
- Accepts full or partial registry paths (e.g., HKLM\Software\Microsoft)
- Supports command-line integration and scripting

#### Use Cases
- Registry analysis and modification
- Accelerating malware analysis and incident response
- Scripting common registry access tasks

[Microsoft Sysinternals - RegJump](https://learn.microsoft.com/en-us/sysinternals/downloads/regjump)


### 3. Strings

*Strings* is a command-line utility that searches executable files (such as .exe, .dll, .sys) for readable ASCII and Unicode strings. It's useful for identifying text, URLs, or embedded commands in binaries.

#### Key Features
- Extracts printable strings from binaries and memory dumps
- Supports Unicode and ANSI string extraction
- Can be used recursively on directories

#### Use Cases
- Reverse engineering malware
- Discovering hardcoded data or credentials
- Analyzing unknown or suspicious files

[Microsoft Sysinternals - Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)

---
# Additional Resources

Below are some additional links to further your knowledge on how to use these tools as a Security Analyst, Security Engineer, or even an Incident Responder:

- [Mark's Blog](https://docs.microsoft.com/en-us/archive/blogs/markrussinovich/)
- [Windows Blog Archive - Mark Russinovich](https://techcommunity.microsoft.com/t5/windows-blog-archive/bg-p/Windows-Blog-Archive/label-name/Mark%20Russinovich)
- [License to Kill: Malware Hunting with Sysinternals Tools (YouTube)](https://www.youtube.com/watch?v=A_TPZxuTzBU)
- [Malware Hunting with Mark Russinovich and the Sysinternals Tools (YouTube)](https://www.youtube.com/watch?v=vW8eAqZyWeo)
