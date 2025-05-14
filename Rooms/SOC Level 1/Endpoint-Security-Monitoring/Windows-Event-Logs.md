# TryHackMe: Windows Event Logs Summary

Room URL: https://tryhackme.com/room/windowseventlogs


# Windows Event Logs 

## Overview of Windows Event Log

Windows Event Log is a crucial component of the Windows operating system that records significant events like system errors, security breaches, and application failures. These logs are essential for troubleshooting, monitoring, and security analysis.

---

## GUI: Using Event Viewer

### Accessing Event Viewer:
- Press `Windows + R`, type `eventvwr.msc`, and press Enter.
- Or search for **Event Viewer** in the Start menu.

### Categories of Logs:
- **Windows Logs**: Application, Security, Setup, System, Forwarded Events
- **Applications and Services Logs**: App-specific logs

### Filtering by Event ID:
1. Open the desired log (e.g., System)
2. Click "Filter Current Log..."
3. Enter Event ID (e.g., `1074`)
4. Click OK

**Example**: Filter for Event ID 1074 to find system shutdown events.

---

## Command Line (CMD)

### Export Logs using `wevtutil`:

```cmd
wevtutil epl System C:\Logs\SystemLog.evtx
```

This exports the system log to a file.

---

## PowerShell for Event Log Analysis

### `Get-EventLog` (classic cmdlet):

```powershell
Get-EventLog -List                      # List available logs
Get-EventLog -LogName System -Newest 10
Get-EventLog -LogName System | Where-Object {$_.EventID -eq 1074}
```

### `Get-WinEvent` (modern, advanced):

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074}
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-1)}
Get-WinEvent -FilterHashtable @{LogName='System'; ID=1074} | Export-Csv -Path C:\Logs\ShutdownEvents.csv -NoTypeInformation
```

---

## What is an Event ID?

Each Windows log entry has a unique **Event ID** indicating the type of event (e.g., login, error, policy change). These IDs are used to **monitor** system activity and **hunt** for threats.

---

## Monitoring with Event IDs

| Event ID | Description                    | Purpose                      |
|----------|--------------------------------|------------------------------|
| 4624     | Successful logon               | Monitor login events         |
| 4625     | Failed logon                   | Detect brute-force attempts  |
| 4688     | Process creation               | Watch for suspicious processes |
| 7045     | New service installed          | Persistence detection        |
| 1102     | Audit log cleared              | Anti-forensics               |
| 4648     | Logon with explicit credentials| Credential misuse            |

[Events to Monitor](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

### PowerShell Example:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | Format-Table TimeCreated, Message -AutoSize
```

---

## Threat Hunting with Event IDs

Threat hunting involves proactive searches for malicious or abnormal behavior.

### Example: Detecting PowerShell from Word (Suspicious Behavior)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {
    $_.Message -like "*powershell*" -and $_.Message -like "*winword*"
} | Format-List TimeCreated, Message
```

---

## Automating Monitoring

### Script to monitor new service installs (Event ID 7045):

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Export-Csv "C:\Logs\NewServiceInstall.csv"
```

Use Task Scheduler or integrate with Defender for Endpoint or SIEM platforms.

---

## Best Practices

1. **Know Your Baseline**: Understand normal behavior to identify anomalies.
2. **Correlate Events**: Combine events like 4624 + 4672 (privileged login).
3. **Use Threat Intelligence**: Align with [MITRE ATT&CK](https://attack.mitre.org/).
4. **Tag Suspicious Patterns**: Monitor for encoded commands, unusual parent-child processes, etc.

---

# task-4: Get-WinEvent [Quesions and Answers] 


## Answer the questions below


Answer the following questions using the [online](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/Get-WinEvent?view=powershell-7.1) help documentation for Get-WinEvent


### Q1. Execute the command from Example 1 (as is). What are the names of the logs related to OpenSSH?

```powershell
Get-WinEvent -ListLog *  | Where-Object {$_.LogName -match 'OpenSSH'}

```

![Screenshot 2025-05-13 122648](https://github.com/user-attachments/assets/ca0bec03-ec5b-4c6c-a065-1243219b5618)

Ans: ***OpenSSH/Admin,OpenSSH/Operational***

### Q2. Execute the command from Example 8. Instead of the string *Policy* search for *PowerShell*. What is the name of the 3rd log provider?

```powershell 
Get-WinEvent -ListProvider *PowerShell*
```
- This command gets the event log providers with names that include a specific string in the provider's name.

![Screenshot 2025-05-13 122953](https://github.com/user-attachments/assets/0251a485-3793-417d-ad7c-9e890de2bff9)

Ans: ***Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager***

### Q3. Execute the command from Example 9. Use Microsoft-Windows-PowerShell as the log provider. How many event ids are displayed for this event provider?

```powershell
(Get-WinEvent -ListProvider Microsoft-Windows-PowerShell).Events | Format-Table Id | Measure-Object
```
- This command lists the Event Ids that the Microsoft-Windows-PowerShell event provider generates. use `Measure-Object
` which counts the number of objects passed through the pipeline.

![Screenshot 2025-05-13 123626](https://github.com/user-attachments/assets/93d244cb-ff44-472d-9bff-d2522678888b)

Ans: ***192***


### Q4. How do you specify the number of events to display?

Ans: ***-MaxEvents***

--- 
# TASK-5: XPath Queries [Quesions and Answers] 

The W3C created **XPath**, or XML Path Language in full, to provide a standard syntax and semantics for addressing parts of an XML document and manipulating strings, numbers, and booleans .


## example 2: create XPath queries for elements within `EventData`

![Screenshot 2025-05-13 132011](https://github.com/user-attachments/assets/74a0b133-5adf-41b6-8cfb-19d8ad873fb5)

![Screenshot 2025-05-13 132654](https://github.com/user-attachments/assets/c71ff58e-7739-4940-b223-06f8fa024201)

```powershell
 Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -FilterXPath '*/System/EventID=4104 and Event/EventData/Data[@Name="ScriptBlockId"]="559319fe-f7ff-4a50-a9a5-91534cb3b4a3"'
```
this is used to retrieve PowerShell script block logging events with a specific ScriptBlockId from the PowerShell Operational event log.

![Screenshot 2025-05-13 132703](https://github.com/user-attachments/assets/4bf0b36d-a562-4057-baf7-143cca79b557)



## Answer the questions below

### Q1.Using the knowledge gained on Get-WinEvent and XPath, what is the query to find WLMS events with a System Time of 2020-12-15T01:09:08.940277500Z?

```powershell
 Get-WinEvent -LogName Application -FilterXPath '*/System/Provider[@Name="WLMS"] and  */System/TimeCreated[@SystemTime="2020-12-15T01:09:08.940277500Z"]'

```
![Screenshot 2025-05-13 134905](https://github.com/user-attachments/assets/8b3ae68f-624c-4a56-8f4b-ac47fe14af84)
 

### Q2.Using Get-WinEvent and XPath, what is the query to find a user named Sam with an Logon Event ID of 4720?


```powershell
Get-WinEvent -LogName Security -FilterXPath '*/EventData/Data[@Name="TargetUserName"]="Sam" and */System/EventID=4720'
```
![Screenshot 2025-05-13 140213](https://github.com/user-attachments/assets/2732785e-299a-40e2-934c-44a1600c0f6b)


# TASK-7: Putting theory into practice

---

## Scenario 1 (Questions 1 & 2): The server admins have made numerous complaints to Management regarding PowerShell being blocked in the environment. Management finally approved the usage of PowerShell within the environment. Visibility is now needed to ensure there are no gaps in coverage. You researched this topic: what logs to look at, what event IDs to monitor, etc. You enabled PowerShell logging on a test machine and had a colleague execute various commands.

### Q1. What event ID is to detect a PowerShell downgrade attack?

 - use filter current log option to filter for event id `400`
 
 ![Screenshot 2025-05-13 214939](https://github.com/user-attachments/assets/a17ea145-d05e-4246-a8a8-dc0e46d870e8)

 - use `View> Group by > Date and Time to group sort by date and time`, since there was test on this event, on Decemeber 18, the attack took on place
 
 ![Screenshot 2025-05-13 215453](https://github.com/user-attachments/assets/a80b3f8a-864d-4de7-affb-19465a6f5a2f)

Ans: ***400***

### Q2. What is the Date and Time this attack took place? (MM/DD/YYYY H:MM:SS [AM/PM])

Ans: ***12/18/2020 7:50:33 AM***

---

## Scenario 2 (Questions 3 & 4) : The Security Team is using Event Logs more. They want to ensure they can monitor if event logs are cleared. You assigned a colleague to execute this action.

### Q3. A Log clear event was recorded. What is the 'Event Record ID'?


- `Evnet Id 104` --> This event is logged when the log file was cleared.
- `Event ID 1102` --> Whenever Windows Security audit log is cleared, event ID 1102 is logged.

(Source)[https://www.socinvestigation.com/most-common-windows-event-ids-to-hunt-mind-map/#:~:text=Event%20ID%201102%2C%20Whenever%20Windows,the%20log%20file%20was%20cleared.]

- use filter current log option to filter for event id `104`.
- and to find the `Event Record Id` and the `computer name`, Search in the XML 

![Screenshot 2025-05-13 232634](https://github.com/user-attachments/assets/693ff50a-359b-47f8-93a8-060a65a6a2a0)

Ans: ***27736***

### Q4. What is the name of the computer?

Ans: ***PC01.example.corp***

---

## Scenario 3 (Questions 5, 6 & 7) : The threat intel team shared its research on Emotet . They advised searching for event ID 4104 and the text "ScriptBlockText" within the EventData element. Find the encoded PowerShell payload.

### Q5. What is the name of the first variable within the PowerShell command?


```powershell
 Get-WinEvent -Path C:\Users\Administrator\Desktop\merged.evtx -FilterXPath '*/System/EventID=4104 and */EventData/Data[@Name="ScriptBlockText"]' -Oldest -MaxEvents 1 | Format-List *
```
- look for the first variable name in the message value

![Screenshot 2025-05-13 223747](https://github.com/user-attachments/assets/52befc4d-2d4e-4f81-bf4e-6200210666c9)


Ans: ***$Va5w3n8***

### Q6. What is the Date and Time this attack took place? (MM/DD/YYYY H:MM:SS [AM/PM])

Ans: ***8/25/2020 10:09:28 PM***

### Q7. What is the Execution Process ID?

Ans: ***6620***

---

## Scenario 4 (Questions 8 & 9) : A report came in that an intern was suspected of running unusual commands on her machine, such as enumerating members of the Administrators group. A senior analyst suggested searching for " C:\Windows\System32\net1.exe". Confirm the suspicion.

### Q8. What is the Group Security ID of the group she enumerated?

- Search for enumeration event id
- 4799(S) ->  A security-enabled local group membership was enumerated

[source](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management)

```powershell
 Get-WinEvent -Path C:\Users\Administrator\Desktop\merged.evtx -FilterXPath '*/System/EventID=4799 and */EventData/Data[@Name="CallerProcessName"]="C:\Windows\System32\net1.exe"' -MaxEvents 1  | format-list *
```
- this command uses `-FilterXPath` to search in the xml. if you dont know what item to inspect in xml, search in the event viewer for this event id and inspect xml items.
- since we have the `callerProsessName` value, you wont need to specify the event ID 

![Screenshot 2025-05-13 231602](https://github.com/user-attachments/assets/ceb9e46f-5c1b-46d0-9fe9-82cab86a704e)

Ans: ***S-1-5-32-544***

### Q9. What is the event ID?

Ans: ***4799***


## Trusted References

- Microsoft Docs: [Get-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog)
- Microsoft Docs: [About Event Logs](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_eventlogs)
- [Ultimate Windows Security - Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---
