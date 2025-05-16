
# TryHackMe Sysmon Room Walkthrough

Room URL: https://tryhackme.com/room/sysmon 

# Table of Contents 
- [Sysmon Overview](#sysmon-overview)
- [TASK-5: Hunting Metasploit](#task-5-hunting-metasploit)
- [TASK-6: Detecting Mimikatz](#task-6-detecting-mimikatz)
- [TASK-7: Hunting Malware](#task-7-hunting-malware)
- [TASK-8: Hunting Persistence](#task-8-hunting-persistence)
- [TASK-9: Detecting Evasion Techniques](#task-9-detecting-evasion-techniques)
- [Practical Investigations](#practical-investigations)


---
# Sysmon Overview

> From Microsoft Docs:  
> *"System Monitor (Sysmon) is a Windows system service and device driver that, once installed, remains resident across system reboots to monitor and log system activity to the Windows event log. It provides detailed information about process creations, network connections, and changes to file creation time. By collecting the events it generates using Windows Event Collection or SIEM agents and analyzing them, you can identify malicious or anomalous activity and understand how intruders and malware operate on your network."*

Sysmon collects detailed, high-quality logs and event tracing that help identify anomalies in your environment. It is commonly used with SIEM systems or log parsing solutions that aggregate, filter, and visualize these events.

- **Startup:** Sysmon starts early during Windows boot.
- **Log Storage:** Events are stored in  
  `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`
- **Ideal Usage:** Forwarding events to a SIEM for analysis.  
  In this room, we focus on viewing events locally via Windows Event Viewer.

---

## Sysmon Configuration Overview

Sysmon requires a configuration file to determine how to analyze received events. You can create your own config or download popular community configs like [SwiftOnSecurity Sysmon-Config](https://github.com/SwiftOnSecurity/sysmon-config) and [ION-Storm config file](https://github.com/ion-storm/sysmon-config/blob/develop/sysmonconfig-export.xml)


- Sysmon supports **29 different Event IDs**, each configurable to specify event handling and analysis.
- Most configurations **prioritize excluding normal events** to reduce noise and decrease manual audit workload in SIEMs.
- Some configs, such as the **ION-Storm sysmon-config fork**, use more **include rules** for a proactive detection approach.
- Configuration preferences vary by SOC teams, so expect to **adapt your config** depending on your monitoring environment and goals.

## Installing Sysmon

> * You can find the Sysmon binary from the [Microsoft Sysinternals website](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Sysmon Best Practices

- **Exclude > Include**  
  Prioritize excluding events over including to avoid missing critical logs and reduce noise.

- **Use CLI for Control**  
  Tools like `Get-WinEvent` and `wevutil.exe` provide granular filtering and control over logs, especially before integrating Sysmon into SIEM or detection platforms.

- **Know Your Environment**  
  Understanding the network environment is crucial to distinguish normal from suspicious activity, enabling effective rule creation.

# TASK-5: Hunting Metasploit

Metasploit is a popular exploit framework used in penetration testing and red team operations. It enables attackers to run exploits on a machine and connect back to a meterpreter shell. Hunting focuses on detecting the meterpreter shell and its behavior.

## Hunting Methodology

- **Network Connections:**  
  Look for network connections originating from suspicious ports, primarily ports **4444** and **5555**, which are commonly used by Metasploit. Any connection on these ports, whether to known or unknown IPs, should be investigated.

For more information about how malware and payloads interact with the network check out the [Malware Common Ports Spreadsheet](https://docs.google.com/spreadsheets/d/17pSTDNpa0sf6pHeRhusvWG6rThciE8CsXTSlDUAZDyo)

- **Process Monitoring:**  
  Investigate suspicious processes that might be related to Metasploit or other Remote Access Trojans (RATs) and command-and-control (C2) beacons.

- **Packet Capture:**  
  Use packet captures from the time of suspicious logs to gather more detailed information about adversary activity.

## Detection Configuration Example

Use the following Sysmon/Ion-Security configuration snippet to detect new network connections on suspicious ports:

```xml
<RuleGroup name="" groupRelation="or">
  <NetworkConnect onmatch="include">
    <DestinationPort condition="is">4444</DestinationPort>
    <DestinationPort condition="is">5555</DestinationPort>
  </NetworkConnect>
</RuleGroup>
```
**PowerShell Hunting Command**

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Metasploit.evtx `
  -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=4444' |
  Format-List message

```
```
Message : Network connection detected:
          RuleName: Usermode
          ProcessId: 3660
          Image: C:\Users\THM-Threat\Downloads\shell.exe
          User: THM\THM-Threat
          Protocol: tcp
          Initiated: true
          SourceIp: 10.10.98.207
          SourcePort: 50872
          DestinationIp: 10.13.4.34
          DestinationPort: 4444
```

the process `shell.exe` located in the user’s Downloads folder is the program that opened the network connection to the destination IP on port 4444. This could be the Metasploit payload or a related malicious executable.

# TASK-6: Detecting Mimikatz

## Mimikatz Overview

Mimikatz is a popular post-exploitation tool commonly used to dump credentials from memory, particularly the LSASS process. It is known for being detected by antivirus solutions due to its recognizable signature, but attackers may use obfuscation or droppers to bypass these defenses.

For detection and hunting, we can:

* Detect file creation with the name "mimikatz".
* Monitor execution from elevated processes.
* Look for process/thread injections.
* Analyze abnormal access to LSASS.

>  Related MITRE ATT\&CK IDs:
>
> * [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
> * [S0002 - Mimikatz](https://attack.mitre.org/software/S0002/)

---

## 1. Detecting File Creation

A simple method to detect Mimikatz is to look for any files created with names containing "mimikatz". This method is not advanced but can catch cases where AV fails.

### Sysmon Rule

```xml
<RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
        <TargetFileName condition="contains">mimikatz</TargetFileName>
    </FileCreate>
</RuleGroup>
```

**PowerShell Hunt Command**

```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" -FilterXPath '*/System/EventID=11' |
Where-Object { $_.Message -like "*mimikatz*" } |
Format-List Message
```

**Example Output**

```
Message : File created:
          Image: C:\Windows\Explorer.EXE
          TargetFilename: C:\Users\THM-Analyst\AppData\Roaming\Microsoft\Windows\Recent\Hunting_Mimikatz.lnk

Message : File created:
          Image: C:\Windows\system32\mmc.exe
          TargetFilename: C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx

Message : File created:
          Image: C:\Windows\system32\mmc.exe
          TargetFilename: C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.exe
```

---

## 2. Hunting Abnormal LSASS Behavior

Credential dumping often targets LSASS. Access to `lsass.exe` by anything other than `svchost.exe` is suspicious.

### Sysmon Rule (Initial)

```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
    </ProcessAccess>
</RuleGroup>
```

### Sysmon Rule (Optimized to exclude svchost.exe)

```xml
<RuleGroup name="" groupRelation="or">
    <ProcessAccess onmatch="exclude">
        <SourceImage condition="image">svchost.exe</SourceImage>
    </ProcessAccess>
    <ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
    </ProcessAccess>
</RuleGroup>
```

**PowerShell Command detecting Mimikatz Activity**


```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Mimikatz.evtx" `
-FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"]="C:\Windows\system32\lsass.exe"' |
Format-List *
```

**Output Breakdown**

```plaintext
Message              : Process accessed:
                       SourceImage: C:\Users\THM-Threat\Downloads\mimikatz.exe
                       TargetImage: C:\Windows\system32\lsass.exe
                       GrantedAccess: 0x1010
                       CallTrace: C:\Windows\SYSTEM32\ntdll.dll+9f644|C:\Windows\System32\KERNELBASE.dll+212ae|...
```

#### `SourceImage`

* Path to the **executable initiating access**.
* In this case: `mimikatz.exe` located in the `Downloads` folder — a strong **indicator of compromise**.

#### `TargetImage`

* The **process being accessed**.
* `lsass.exe` is responsible for handling credentials — access to it is highly suspicious.

#### `GrantedAccess: 0x1010`

* Windows access rights granted to the source process:

  * `PROCESS_QUERY_INFORMATION` (0x0400)
  * `PROCESS_VM_READ` (0x0010)
* Indicates **memory read access**, used to extract credentials from LSASS.

#### `CallTrace`

* **Stack trace** of the access event.
* Shows the exact **system libraries and memory addresses** used.
* Includes references to `ntdll.dll`, `KERNELBASE.dll`, and the `mimikatz.exe` binary.


### Why This Is Suspicious

* This is a classic example of **credential dumping behavior**.
* No legitimate application should access `lsass.exe` from a user directory.
* Seeing `mimikatz.exe` with memory read permissions on `lsass.exe` is a strong indicator of compromise or red-team simulation.


>  Tip: Always monitor for processes accessing `lsass.exe` and investigate any that do not originate from a known, signed binary like `svchost.exe` or `lsass.exe` itself.


# TASK-7: Hunting Malware

## Malware Overview

Malware can serve many purposes, but this overview focuses on **Remote Access Trojans (RATs)** and **Backdoors**:

- **RATs** (e.g., Xeexe, Quasar) enable attackers to gain remote access and control over a system. They often include evasion techniques and a user-friendly interface.
- **Backdoors** provide persistent unauthorized access to a system, bypassing normal authentication.

Detection begins with **hypothesis-based hunting**, such as monitoring for open backconnect ports.

 [MITRE ATT&CK - Software](https://attack.mitre.org/software/)

## 1. Hunting Rats and C2 Servers

### Detecting Backconnect Ports Used by RATs

In this scenario, we focused on detecting **Remote Access Trojans (RATs)** by monitoring specific network activity. RATs often open reverse shells or connect back to an attacker's server over suspicious ports like `8080`, `1034`, or `1604`.

To detect this, the **Ion-Storm Sysmon configuration file** is used to:

* **Include specific destination ports** for alerting.
* **Exclude benign processes** like `OneDrive.exe` to reduce false positives.

```xml
<RuleGroup name="" groupRelation="or">
	<NetworkConnect onmatch="include">
		<DestinationPort condition="is">1034</DestinationPort>
		<DestinationPort condition="is">1604</DestinationPort>
	</NetworkConnect>
	<NetworkConnect onmatch="exclude">
		<Image condition="image">OneDrive.exe</Image>
	</NetworkConnect>
</RuleGroup>
```

>  **Note:** Be cautious with what you exclude. For example, some versions of this configuration file exclude port 53 (used by DNS), but attackers may abuse this port to bypass detections.

### PowerShell Detection Example

The following PowerShell command hunts for RAT activity by detecting connections on port `8080`:

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080' -MaxEvents 1 | Format-List *
```

### Example Log Output:

```
Message              : Network connection detected:
                       RuleName: -
                       UtcTime: 2021-01-05 04:44:33.963
                       ProcessGuid: {6cd1ea62-ed72-5ff3-c107-00000000f500}
                       ProcessId: 6200
                       Image: C:\Users\THM-Threat\Downloads\bigbadrat.exe
                       User: THM\THM-Threat
                       Protocol: tcp
                       Initiated: true
                       SourceIp: 10.10.98.207
                       DestinationIp: 10.13.4.34
                       DestinationPort: 8080
```


By actively hunting for connections over suspicious ports—especially when tied to unknown executables—we can detect potential RAT behavior on endpoints. Use this technique as part of a layered hypothesis-driven approach to uncover hidden malware communicating with remote adversaries.



# TASK-8: Hunting Persistence

Persistence allows attackers to maintain access to a compromised machine. There are many techniques for achieving persistence, but this summary focuses on registry modifications and startup scripts. Sysmon can be used to hunt for persistence by monitoring File Creation and Registry Modification events. The SwiftOnSecurity Sysmon configuration helps detect these techniques effectively. Additionally, using Rule Names to filter events helps reduce noise and focus on suspicious activity in the event logs.

## 1. Hunting Startup Persistence

### Technique Reference

* **MITRE ATT\&CK ID:** [T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
* Previously referenced as **T1023** (Start Menu) and **T1165** (Startup folder)

Attackers commonly achieve **persistence** by placing malicious executables in the `Startup` or `Start Menu` directories. Files in these directories are executed automatically when the user logs in.

### Detection Configuration (SwiftOnSecurity Style)

```xml
<RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
        <TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>
        <TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>
    </FileCreate>
</RuleGroup>
```
**Powershell command to filter logs based on the RuleName `T1023`**

```powershell
 Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1023.evtx -FilterXPath '*/EventData/Data[@Name="RuleName"]="T1023"' -MaxEvents 1 | Format-List *

```

**Result**

```
RuleName: T1023
UtcTime: 2020-12-21 17:50:27.760
ProcessGuid: {b79b1e30-e015-5fe0-4408-00000000f500}
ProcessId: 6736
Image: C:\Windows\system32\notepad.exe
TargetFilename: C:\Users\THM-Threat\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\persist.exe
CreationUtcTime: 2020-12-21 17:50:27.682
```

### Explanation

In this suspicious event, a legitimate system process `notepad.exe` was used to drop `persist.exe` into the **Startup folder**:

* **Notepad.exe is unlikely to write executable files** — especially to persistence locations. This indicates one of the following:

  1. **Process injection:** Malicious code was injected into `notepad.exe`, making it the parent process of the persistence payload.
  2. **Masquerading:** A malicious executable was renamed to `notepad.exe` and executed to appear trustworthy.
  3. **LOLBins abuse:** `notepad.exe` may have been launched by a script to act as a decoy while another thread dropped the payload.

This technique enables **stealthy persistence** and evasion of basic monitoring solutions.

---

## 2. Hunting Registry Key Persistence

### Technique Reference

* **MITRE ATT\&CK ID:** [T1112 – Modify Registry](https://attack.mitre.org/techniques/T1112/)
* Also related to: [T1547.001 – Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)


This technique involves the **modification or deletion** of registry keys that control automatic application execution on startup. Adversaries may add or remove values in these keys to manipulate persistent behavior.

### Detection Configuration (SwiftOnSecurity Style)

```xml
<RuleGroup name="" groupRelation="or">
    <RegistryEvent onmatch="include">
        <TargetObject name="T1060,RunKey" condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject name="T1484" condition="contains">Group Policy\Scripts</TargetObject>
        <TargetObject name="T1060" condition="contains">CurrentVersion\Windows\Run</TargetObject>
    </RegistryEvent>
</RuleGroup>
```
**Powershell command to filter logs based on the RuleName `T1060,RunKey`**

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\T1060.evtx -FilterXPath '*/EventData/Data[@Name="RuleName"]="T1060,RunKey"' -MaxEvents 1 | Format-List *           
``` 

**Result**

```
RuleName: T1060,RunKey
EventType: DeleteValue
UtcTime: 2020-12-21 19:44:33.887
ProcessGuid: {b79b1e30-f938-5fe0-7c08-00000000f500}
ProcessId: 1808
Image: C:\Windows\regedit.exe
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\New Value #2
```

### Explanation

* `regedit.exe` was used to delete a value in the **Run key**, a location typically used for establishing persistence.
* Deleting a registry value from `HKLM\...\Run` could indicate:

  1. **An attacker cleaning up evidence** of a previously established persistence mechanism.
  2. **A defender or cleanup script** removing malware from autostart configuration.

In either case, the event is important during incident response because it reflects **tampering with autostart configuration**, often tied to malware behavior.

---

## Recommendations for Analysts

* Correlate `FileCreate` and `RegistryEvent` logs with `ProcessCreate` (Sysmon ID 1) to identify the parent-child relationship.
* Validate executables using hash lookups (e.g., VirusTotal).
* Monitor for legitimate binaries behaving suspiciously, like `notepad.exe` or `regedit.exe` modifying startup behavior.
* Use MITRE ATT\&CK mappings to align detection and alerting rules with known techniques.

---

## Resources

* MITRE ATT\&CK Tactics & Techniques: [https://attack.mitre.org](https://attack.mitre.org)
* SwiftOnSecurity SysmonConfig: [https://github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
* Malware persistence via startup folder: [https://www.malware-traffic-analysis.net/](https://www.malware-traffic-analysis.net/)
* Registry persistence techniques: [https://www.sans.org/blog/persistence-part-1-run-keys/](https://www.sans.org/blog/persistence-part-1-run-keys/)


---
# TASK-9: Detecting Evasion Techniques

## Evasion Techniques Overview

Attackers use evasion techniques to bypass antivirus and detection systems. Two common methods include:

- **Alternate Data Streams (ADS):** Used to hide malicious files by storing them in hidden NTFS streams.
- **Injection Techniques:** Methods like DLL Injection allow malicious code to run inside legitimate processes.

### MITRE ATT&CK References

- [T1564.004 – Hide Artifacts: NTFS File Attributes (ADS)](https://attack.mitre.org/techniques/T1564/004/)
- [T1055 – Process Injection](https://attack.mitre.org/techniques/T1055/)

## 1.Hunting Alternate Data Streams (ADS)

**Alternate Data Streams (ADS)** are a feature of NTFS file systems that allow data to be stored in hidden streams attached to a file. Malware authors use ADS to hide payloads, scripts, or malicious content that evade traditional file detection tools.

### Purpose of the Hunt

We are leveraging **Sysmon Event ID 15** (`FileCreateStreamHash`) to detect the creation of these hidden data streams, focusing on suspicious locations such as:

* **Downloads** folder
* **Temp** subfolders like `Temp\7z`
* Files ending in **.hta** (HTML Applications)
* Files ending in **.bat** (Batch Scripts)

>  These are common places or formats used by malware to hide execution code.


### Sysmon Config Snippet Used

```xml
<RuleGroup name="" groupRelation="or">
	<FileCreateStreamHash onmatch="include">
		<TargetFilename condition="contains">Downloads</TargetFilename>
		<TargetFilename condition="contains">Temp\7z</TargetFilename>
		<TargetFilename condition="ends with">.hta</TargetFilename>
		<TargetFilename condition="ends with">.bat</TargetFilename>
	</FileCreateStreamHash>
</RuleGroup>
```
**Powershell command to filter log based on the image name**

```powershell
Get-WinEvent -Path .\Hunting_ADS.evtx -FilterXPath '*/EventData/Data[@Name="Image"]="C:\Windows\System32\cmd.exe"' | Format-List message
```

**Result**

1. **File Creation in Startup Folder**

```
Image: C:\Windows\system32\cmd.exe
TargetFilename: C:\Users\THM-Threat\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RunWallpaperSetup.cmd
```

* **Why it matters**: ADS often target the Startup folder to maintain persistence while hiding their presence.

2. **Repeated Execution of cmd.exe with Script in Startup Folder**

```
CommandLine: C:\Windows\system32\cmd.exe /c ""C:\Users\THM-Threat\AppData\Roaming\...\RunWallpaperSetupInit.cmd""
ParentImage: C:\Windows\explorer.exe
```

* **Why it matters**: The use of `cmd.exe` to execute a script from Startup is a persistence method (MITRE ATT\&CK T1547.001).
* **Red Flag**: The command was run at logon via `explorer.exe` (suggests auto-execution).

3. **Use of `type` command on a Startup Script**

```
CommandLine: C:\Windows\system32\cmd.exe /S /D /c" type ...RunWallpaperSetupInit.cmd"
```

* **Why it matters**: Using `type` without redirection is unusual. This may be used to:

  * Dump contents
  * Validate script before execution
  * Interact with Alternate Data Streams (e.g., `file.txt:hidden`)

---

## Likely Attack Flow

1. Attacker drops a `.cmd` file (possibly containing an ADS payload) into the Startup folder.
2. On user logon, `explorer.exe` launches the script via `cmd.exe`.
3. The script or ADS payload is executed.
4. The `type` command is used to read or activate hidden stream content.



---

## 2. Detecting Remote Threads


Remote thread creation is a technique often used by adversaries to evade detection by injecting code into other running processes. This can be part of several attack methods such as:

* **DLL Injection**
* **Thread Hijacking**
* **Process Hollowing**

Using **Sysmon Event ID 8**, defenders can monitor remote thread creation. The SwiftOnSecurity Sysmon configuration provides a balanced rule to detect suspicious behavior by excluding common benign cases (e.g., `svchost.exe` into Chrome).

### Key MITRE ATT\&CK Techniques Involved:

* **[T1055](https://attack.mitre.org/techniques/T1055/)**: Process Injection
* **[T1055.001](https://attack.mitre.org/techniques/T1055/001/)**: Dynamic-link Library Injection
* **[T1055.003](https://attack.mitre.org/techniques/T1055/003/)**: Thread Execution Hijacking

### Sysmon Rule Snippet (SwiftOnSecurity)

```xml
<RuleGroup name="" groupRelation="or">
	<CreateRemoteThread onmatch="exclude">
		<SourceImage condition="is">C:\Windows\system32\svchost.exe</SourceImage>
		<TargetImage condition="is">C:\Program Files (x86)\Google\Chrome\Application\chrome.exe</TargetImage>
	</CreateRemoteThread>
</RuleGroup>
```

**Powershell command to filter for event ID**

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Practice\Detecting_RemoteThreads.evtx -FilterXPath '*/System/EventID=8' | Format-List *
```

**Reuslt**
```
Message              : CreateRemoteThread detected:
                       RuleName:
                       UtcTime: 2019-07-03 20:39:30.254
                       SourceProcessGuid: {365abb72-0c16-5d1d-0000-00108b721100}
                       SourceProcessId: 3092
                       SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                       TargetProcessGuid: {365abb72-1256-5d1d-0000-0010fb1a1b00}
                       TargetProcessId: 1632
                       TargetImage: C:\Windows\System32\notepad.exe
                       NewThreadId: 3148
                       StartAddress: 0x00540000
                       StartModule:
                       StartFunction:
```

### Explanation

- **SourceImage**: This is the process initiating the remote thread (i.e., the attacker or script).
- **TargetImage**: This is the victim process where the remote thread is being injected.
- `powershell.exe` (controlled by attacker) is injecting code into `notepad.exe` to hide execution, evade detection, or execute shellcode.



# Practical Investigations

## Investigation 1 - ugh, BILL THAT'S THE WRONG USB!

In this investigation, your team has received reports that a malicious file was dropped onto a host by a malicious USB. They have pulled the logs suspected and have tasked you with running the investigation for it.

### Q1.1. What is the full registry key of the USB device calling svchost.exe in Investigation 1? 

**Filter the log based on the event id 13 -> Registry value set event**
```powershell
 Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=13' |Format-List *
```
**Output:**
```
Message              : Registry value set:
RuleName             : SetValue
ProcessGuid          : 616
ProcessId            : 0
Image                :  HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBS
                       TOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName
TargetObject         : U

```
A registry value was set involving a SanDisk U3 Cruzer Micro USB device, as recorded by Sysmon Event ID 13. The registry path indicates that the system detected or interacted with this USB device. No specific process was linked to the change (ProcessId: 0), which suggests it have been system-initiated or hardware-driven.

Ans: ***HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName***

### Q1.2. What is the device name when being called by RawAccessRead in Investigation 1?

**RawAccessRead EventID -> 9**

```powershell
Get-WinEvent -Path C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx -FilterXPath '*/System/EventID=9' |Format-List *
```
**Output:**

```
Message              : RawAccessRead detected:
                       ProcessGuid: 1388
                       ProcessId: 0
                       Image: \Device\HarddiskVolume3
                       Device: %6
```
A raw access read was detected, indicating that a process attempted to read a disk at a low level (bypassing the file system).

Ans: ***\Device\HarddiskVolume3***

### Q1.3. What is the first exe the process executes in Investigation 1?

**Filter based on the evetID -> Processes Creat**
```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-1.evtx" -FilterXPath '*/System/EventID=1' |
>> Select-Object -ExpandProperty Message |
>> Select-String "Image:|CommandLine:|ParentProcessGuid:"


```

**Output**

```
Process Create:
RuleName: 2018-03-06 06:57:51.132
ProcessGuid: 3348
ProcessId: 0
Image: 6.1.7600.16385 (win7_rtm.090713-1255)
FileVersion: Windows Calculator
Description: Microsoft® Windows® Operating System
Product: Microsoft Corporation
Company: calc.exe
OriginalFileName: C:\Windows\system32\
CommandLine: WIN-7JKBJEGBO38\q
ParentProcessGuid: C:\Windows\System32\rundll32.exe
```
This log shows that `calc.exe` was executed via `rundll32.exe` by user q. While launching Calculator isn’t malicious by itself, the context and parent process (`rundll32.exe`) strongly suggest this was a code execution test, possibly triggered by a script or payload delivered via USB — consistent with earlier raw disk access and registry activity.

---

## Investigation 2 - This isn't an HTML file? 

Another suspicious file has appeared in your logs and has managed to execute code masking itself as an HTML file, evading your anti-virus detections. Open the logs and investigate the suspicious file.  


**Filter the log based on the network connection events**
```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx" -FilterXPath '*/System/EventID=3'| Format-List  Message
```
**Output:**
```
Message : Network connection detected:
          RuleName:
          ProcessId: 652
          Image: C:\Windows\System32\mshta.exe
          User: IEWIN7\IEUser
          Protocol: tcp
          Initiated: true
          SourceIp: 10.0.2.13
          SourceHostname: IEWIN7
          SourcePort: 49159
          DestinationIsIpv6: false
          DestinationIp: 10.0.2.18
          DestinationPort: 4443

```
That script established a network connection to a remote system (`10.0.2.18:4443`)

**Filter  the log based on the preocess creation events**

```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-2.evtx" -FilterXPath '*/System/EventID=1'| Format-List  Message
```
**Output-2**

```
Message : Process Create:
          RuleName:
          ProcessId: 652
          Image: C:\Windows\System32\mshta.exe
          Description: Microsoft (R) HTML Application host
          Product: Internet Explorer
          Company: Microsoft Corporation
          OriginalFileName: "C:\Windows\System32\mshta.exe" "C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary
          Internet Files\Content.IE5\S97WTYG7\update.hta"
          CommandLine: C:\Users\IEUser\Desktop\
          CurrentDirectory: IEWIN7\IEUser
          ParentProcessGuid: 3660
          ParentProcessId: 0
          ParentImage: "C:\Program Files\Internet Explorer\iexplore.exe" C:\Users\IEUser\Downloads\update.html

```

- `mshta.exe` A Windows utility used to run `.HTA` (HTML Applications).
-  the parent process `iexplore.exe` opened `update.html`, which then automatically or indirectly launched `update.hta` using `mshta.exe`.

### Q2.1. What is the full path of the payload in Investigation 2?


Ans: ***C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta***

### Q2.2. What is the full path of the file the payload masked itself as in Investigation 2?

- `update.hta` Masquerading as `update.html`
- The attacker crafted a file named `update.html`, but it either
   - Redirected to `update.hta` (via `<meta>`, `<script>`, etc.)
   - Or was actually an `.hta` file renamed or disguised as `.html` (some browsers mishandle MIME types or file extensions)

Ans: ***C:\Users\IEUser\Downloads\update.html***

### Q2.3. What signed binary executed the payload in Investigation 2?

- The signed binary that executed the malicious payload was `mshta.exe`, a Microsoft-signed tool designed to run HTML Application (`.hta`) files.
Ans: ***C:\Windows\System32\mshta.exe***

### Q2.4 What is the IP of the adversary in Investigation 2?

Ans: ***10.0.2.18***

### Q2.5 What back connect port is used in Investigation 2?

- [Port 4443 Details](https://www.speedguide.net/port.php?port=4443)
Ans: ***4443***


---

## Investigation 3.1 - 3.2 - Where's the bouncer when you need him

Your team has informed you that the adversary has managed to set up persistence on your endpoints as they continue to move throughout your network. Find how the adversary managed to gain persistence using logs provided.
Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx`
and `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx.`

### Q3.1 What is the IP of the suspected adversary in Investigation 3.1?

**Filter based on the network connection events**
```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx" -FilterXPath '*/System/EventID=3'| Format-List  Message
```

**Output:**
```
Message : Network connection detected:
          ProcessGuid: 12224
          ProcessId: 0
          Image: DESKTOP-O153T4R\q
          User: tcp
          Protocol: true
          Initiated: false
          SourceIsIpv6: 172.16.199.179
          SourcePortName: false
          DestinationIsIpv6: 172.30.1.253
          DestinationIp: empirec2
          DestinationHostname: 80
          DestinationPort: 0
          DestinationPortName: %18
```

Ans: ***172.30.1.253***

### Q3.2 What is the hostname of the affected endpoint in Investigation 3.1?

Ans: ***DESKTOP-O153T4R***

### Q3.3 What is the hostname of the C2 server connecting to the endpoint in Investigation 3.1?
Ans: ***empirec2***

### Q3.4 Where in the registry was the payload stored in Investigation 3.1?
**Filter the log based on the Registry value set -> 13**

```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.1.evtx" -FilterXPath '*/System/EventID=13'| Format-List  Message
```
**Output:**
```
Message : Registry value set:
          RuleName: SetValue
          ProcessGuid: 12224
          ProcessId: 0
          Image: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger
          TargetObject: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp
          HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;
          Details: %8

Message : Registry value set:
          RuleName: SetValue
          ProcessGuid: 12224
          ProcessId: 0
          Image: HKLM\SOFTWARE\Microsoft\Network\debug
          TargetObject: SQBGACgAJABQAFMAV....
```

1. First Registry Modification (Debugger Hijack)
  - `sethc.exe` is the Sticky Keys executable — it runs when you press Shift 5 times at the login screen.
  -  By setting a Debugger value for it, the attacker makes any call to `sethc.exe` instead launch a custom PowerShell payload.
  -  The command grabs the contents of: `HKLM:\Software\Microsoft\Network\debug` ...and runs it as an encoded PowerShell command using `-enc`.
  - This gives the attacker code execution at the login screen — even without credentials!
2. Second Registry Modification (Payload Storage)
  - The attacker stored the base64-encoded PowerShell payload in this registry key.
  - That payload is retrieved and run when `sethc.exe` is triggered.

the goal is to gain persistence, the attacker sets this up so they can regain access even if they lose their remote session.

Ans: ***HKLM\SOFTWARE\Microsoft\Network\debug***

### Q3.5 What PowerShell launch code was used to launch the payload in Investigation 3.1?

Ans: ***"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -c "$x=$((gp HKLM:Software\Microsoft\Network debug).debug);start -Win Hidden -A \"-enc $x\" powershell";exit;***

### Q3.6 What is the IP of the adversary in Investigation 3.2?

**Filter the log based on Network Connections**

```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx" -FilterXPath '*/System/EventID=3'| Format-List  Message
```
```
Message : Network connection detected:
          ProcessGuid: 11020
          ProcessId: 0
          Image: DESKTOP-O153T4R\q
          User: tcp
          Protocol: true
          Initiated: false
          SourceIsIpv6: 172.168.103.167
          SourceIp: DESKTOP-O153T4R.SSG-350M
          SourcePort: 0
          SourcePortName: false
          DestinationIsIpv6: 172.168.103.188
          DestinationIp: ACA867BC.ipt.aol.com
          DestinationHostname: 80
```

Ans: ***172.168.103.188***

### Q3.7 What is the full path of the payload location in Investigation 3.2?


```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx" -FilterXPath '*/System/EventID=1'| Format-List  Message
```

```
Message : 
          Company: "C:\WINDOWS\system32\cmd.exe" /C "echo SQBmACgAJ... > c:\users\q\AppData:blah.txt"

```
- The attacker used registry keys to persist malicious payloads.
- `sethc.exe` was hijacked to serve as a trigger to launch the payload.
- The actual payload is stored in the registry in an encoded format.
- An additional base64-encoded script is written to a user's `AppData`, possibly as a backup or alternate method. 
- These techniques are used to:
    - Bypass security software
    - Avoid dropping files directly on disk
    - Maintain persistence after reboots
Ans: ***c:\users\q\AppData:blah.txt***

### Q3.8 What was the full command used to create the scheduled task in Investigation 3.2?

```powershell
Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx" -FilterXPath '*/System/EventID=1'| Format-List  message

```
**Output:**

```
Message : Process Create:
          Image: 10.0.16299.15 (WinBuild.160101.0800)
          FileVersion: Task Scheduler Configuration Tool
          Description: Microsoft® Windows® Operating System
          Product: Microsoft Corporation
          Company: "C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR
          "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX
          ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more <
          c:\users\q\AppData:blah.txt'''))))\""
          OriginalFileName: C:\Users\q\
          CommandLine: DESKTOP-O153T4R\q
          ParentProcessGuid: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```
- A scheduled task named `Updater` is created to run daily at 09:00.
- The task executes a hidden, non-interactive PowerShell session.
- It runs code read from the file created earlier (`blah.txt`) by decoding its Base64 content and invoking it via `IEX `(Invoke-Expression).
- This is a persistence mechanism, the attacker ensures the payload (initially staged) is executed regularly using Task Scheduler.

Ans: ***“C:\WINDOWS\system32\schtasks.exe” /Create /F /SC DAILY /ST 09:00 /TN Updater /TR “C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \”IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ‘’more < c:\users\q\AppData:blah.txt’’’))))\””***

### Q3.9 What process was accessed by schtasks.exe that would be considered suspicious behavior in Investigation 3.2?

```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-3.2.evtx" -FilterXPath '*/System/EventID=10' | ForEach-Object {
>>     $xml = [xml]$_.ToXml()
>>     $eventData = $xml.Event.EventData.Data
>>     $sourceImage = $eventData | Where-Object { $_.Name -eq "SourceImage" }
>>     $targetImage = $eventData | Where-Object { $_.Name -eq "TargetImage" }
>>
>>     [PSCustomObject]@{
>>         TimeCreated = $_.TimeCreated
>>         SourceImage = $sourceImage.'#text'
>>         TargetImage = $targetImage.'#text'
>>     }
>> }

TimeCreated         SourceImage                   TargetImage
-----------         -----------                   -----------
2/5/2018 7:08:53 AM C:\WINDOWS\system32\lsass.exe C:\WINDOWS\system32\schtasks.exe
2/5/2018 7:08:53 AM C:\WINDOWS\system32\lsass.exe C:\WINDOWS\system32\schtasks.exe
```
- Reads Sysmon Event ID 10 logs, extracts key data from each event: source process and target process
- Outputs this data in a clean and readable object format 
- If `schtasks.exe` accessed lsass.exe, that is highly suspicious.
   - why?
     - `lsass.exe` stores user credentials, password hashes, and tokens.
     - It's commonly targeted by malware for credential dumping (e.g., Mimikatz).
     - `schtasks.exe` is a benign Windows utility, not supposed to read or inject into `lsass.exe`

Ans: ***lsass.exe***


---

## Investigation 4 - Mom look! I built a botnet!

As the adversary has gained a solid foothold onto your network it has been brought to your attention that they may have been able to set up C2 communications on some of the endpoints. Collect the logs and continue your investigation.

Logs are located in `C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-4.evtx`.

### Q4.1 What is the IP of the adversary in Investigation 4?


```powershell
 Get-WinEvent -Path "C:\Users\THM-Analyst\Desktop\Scenarios\Investigations\Investigation-4.evtx" -FilterXPath '*/System/EventID=3'| Format-List  m*

Message         : Network connection detected:
                  ProcessGuid: 7412
                  ProcessId: 0
                  Image: NT AUTHORITY\SYSTEM
                  User: tcp
                  Protocol: true
                  SourceIsIpv6: 172.16.199.179
                  SourceIp: DESKTOP-O153T4R.localdomain
                  SourceHostname: 49867
                  SourcePort: 0
                  DestinationIsIpv6: 172.30.1.253
                  DestinationIp: empirec2
                  DestinationHostname: 80
```
Ans: ***172.30.1.253***


### Q4.2 What port is the adversary operating on in Investigation 4?


Ans: ***80***

### Q4.3 What C2 is the adversary utilizing in Investigation 4?

Ans: ***Empire***
